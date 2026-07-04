import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	DEFAULT_MAX_BYTES,
	DEFAULT_MAX_LINES,
	formatSize,
	truncateTail,
	withFileMutationQueue,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const VALID_ACTIONS = new Set(["test", "ps", "cmd", "copy", "fetch"]);
const MAX_CAPTURE_BYTES = 10 * 1024 * 1024;

interface WinrmParams {
	action: string;
	script?: string;
	command?: string;
	file?: string;
	localPath?: string;
	remotePath?: string;
	host?: string;
	user?: string;
	passwordEnv?: string;
	passwordFile?: string;
	envFile?: string;
	port?: number;
	ssl?: boolean;
	certValidation?: boolean;
	auth?: string;
	connectionTimeout?: number;
	readTimeout?: number;
	operationTimeout?: number;
	noProxy?: boolean;
}

interface ProcessResult {
	stdout: string;
	stderr: string;
	exitCode: number | null;
	signal: string | null;
}

function findHelper(start: string): string {
	let current = resolve(start);
	for (;;) {
		const helper = join(current, ".pi", "skills", "winrm", "scripts", "winrm.py");
		if (existsSync(helper)) return helper;

		const parent = resolve(current, "..");
		if (parent === current) break;
		current = parent;
	}

	return join(resolve(start), ".pi", "skills", "winrm", "scripts", "winrm.py");
}

function addOptional(args: string[], flag: string, value: string | number | boolean | undefined) {
	if (value === undefined || value === null || value === "") return;
	args.push(flag, String(value));
}

function buildArgs(params: WinrmParams): string[] {
	const action = params.action;
	if (!VALID_ACTIONS.has(action)) {
		throw new Error(`Invalid WinRM action '${action}'. Expected one of: ${Array.from(VALID_ACTIONS).join(", ")}`);
	}

	const args: string[] = [];
	addOptional(args, "--host", params.host);
	addOptional(args, "--user", params.user);
	addOptional(args, "--password-env", params.passwordEnv);
	addOptional(args, "--password-file", params.passwordFile);
	addOptional(args, "--env-file", params.envFile);
	addOptional(args, "--port", params.port);
	addOptional(args, "--ssl", params.ssl);
	addOptional(args, "--cert-validation", params.certValidation);
	addOptional(args, "--auth", params.auth);
	addOptional(args, "--connection-timeout", params.connectionTimeout);
	addOptional(args, "--read-timeout", params.readTimeout);
	addOptional(args, "--operation-timeout", params.operationTimeout);
	if (params.noProxy) args.push("--no-proxy");

	args.push(action);

	if (action === "ps") {
		if (params.file) {
			args.push("--file", params.file);
		} else if (params.script) {
			args.push("--script", params.script);
		} else {
			throw new Error("WinRM action 'ps' requires either 'script' or 'file'.");
		}
	}

	if (action === "cmd") {
		if (!params.command) throw new Error("WinRM action 'cmd' requires 'command'.");
		args.push("--command", params.command);
	}

	if (action === "copy") {
		if (!params.localPath || !params.remotePath) {
			throw new Error("WinRM action 'copy' requires 'localPath' and 'remotePath'.");
		}
		args.push(params.localPath, params.remotePath);
	}

	if (action === "fetch") {
		if (!params.remotePath || !params.localPath) {
			throw new Error("WinRM action 'fetch' requires 'remotePath' and 'localPath'.");
		}
		args.push(params.remotePath, params.localPath);
	}

	return args;
}

function runProcess(command: string, args: string[], cwd: string, signal?: AbortSignal): Promise<ProcessResult> {
	return new Promise((resolvePromise, reject) => {
		const child = spawn(command, args, {
			cwd,
			env: process.env,
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";
		let capturedBytes = 0;
		let captureExceeded = false;

		const capture = (chunk: Buffer, stream: "stdout" | "stderr") => {
			capturedBytes += chunk.length;
			if (capturedBytes > MAX_CAPTURE_BYTES) {
				captureExceeded = true;
				child.kill("SIGTERM");
				return;
			}

			if (stream === "stdout") stdout += chunk.toString("utf8");
			else stderr += chunk.toString("utf8");
		};

		child.stdout.on("data", (chunk: Buffer) => capture(chunk, "stdout"));
		child.stderr.on("data", (chunk: Buffer) => capture(chunk, "stderr"));

		const abort = () => child.kill("SIGTERM");
		signal?.addEventListener("abort", abort, { once: true });

		child.on("error", (err) => {
			signal?.removeEventListener("abort", abort);
			reject(err);
		});

		child.on("close", (exitCode, closeSignal) => {
			signal?.removeEventListener("abort", abort);
			if (captureExceeded) {
				stderr += `\nOutput exceeded capture limit (${MAX_CAPTURE_BYTES} bytes); process terminated. Narrow the remote query.\n`;
			}
			resolvePromise({ stdout, stderr, exitCode, signal: closeSignal });
		});
	});
}

async function formatOutput(output: string): Promise<{ text: string; fullOutputPath?: string }> {
	const truncation = truncateTail(output, {
		maxLines: DEFAULT_MAX_LINES,
		maxBytes: DEFAULT_MAX_BYTES,
	});

	let text = truncation.content;
	if (!truncation.truncated) return { text };

	const tempDir = await mkdtemp(join(tmpdir(), "pi-winrm-"));
	const fullOutputPath = join(tempDir, "output.txt");
	await withFileMutationQueue(fullOutputPath, async () => {
		await writeFile(fullOutputPath, output, "utf8");
	});

	text += `\n\n[Output truncated: showing ${truncation.outputLines} of ${truncation.totalLines} lines`;
	text += ` (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}).`;
	text += ` Full output saved to: ${fullOutputPath}]`;

	return { text, fullOutputPath };
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "winrm",
		label: "WinRM",
		description:
			"Run authorized Windows lab operations over WinRM for this project. Supports actions: test, ps, cmd, copy, fetch. Credentials are read from environment variables or .local/winrm.env; do not pass passwords.",
		promptSnippet: "Run authorized PowerShell/cmd/copy/fetch tasks on the configured Windows lab host over WinRM.",
		promptGuidelines: [
			"Use winrm only for operator-authorized Windows lab hosts related to this Challenger SIEM project.",
			"winrm current authorized local Windows lab VM: 192.168.122.240.",
			"Use winrm for E2E agent validation from the VM; target the API on this host at http://192.168.122.1:4444, not 127.0.0.1.",
			"Do not pass, print, or store WinRM passwords/tokens in prompts, command arguments, logs, or tracked files; winrm reads secrets from .local/winrm.env or environment variables.",
			"Ask before winrm performs reboots, firewall/authentication changes, service uninstall, data deletion, or event-log clearing.",
			"Keep winrm output bounded with targeted PowerShell filters such as -MaxEvents, Select-Object -First, and precise service or path names.",
		],
		parameters: Type.Object({
			action: Type.String({ description: "One of: test, ps, cmd, copy, fetch" }),
			script: Type.Optional(Type.String({ description: "PowerShell script text for action=ps" })),
			command: Type.Optional(Type.String({ description: "cmd.exe command line for action=cmd" })),
			file: Type.Optional(Type.String({ description: "Local PowerShell script file whose contents are run remotely for action=ps" })),
			localPath: Type.Optional(Type.String({ description: "Local file path for copy/fetch" })),
			remotePath: Type.Optional(Type.String({ description: "Remote Windows path for copy/fetch" })),
			host: Type.Optional(Type.String({ description: "Override CHALLENGER_WINRM_HOST" })),
			user: Type.Optional(Type.String({ description: "Override CHALLENGER_WINRM_USER" })),
			passwordEnv: Type.Optional(Type.String({ description: "Name of env var containing the password; never pass the password itself" })),
			passwordFile: Type.Optional(Type.String({ description: "Path to file containing password; prefer ignored .local files" })),
			envFile: Type.Optional(Type.String({ description: "Env file to load, default .local/winrm.env; use 'none' to disable" })),
			port: Type.Optional(Type.Number({ description: "WinRM port" })),
			ssl: Type.Optional(Type.Boolean({ description: "Use HTTPS WinRM" })),
			certValidation: Type.Optional(Type.Boolean({ description: "Validate HTTPS server certificates" })),
			auth: Type.Optional(Type.String({ description: "Auth mechanism, e.g. negotiate, ntlm, kerberos, basic" })),
			connectionTimeout: Type.Optional(Type.Number({ description: "HTTP connection timeout seconds" })),
			readTimeout: Type.Optional(Type.Number({ description: "HTTP read timeout seconds" })),
			operationTimeout: Type.Optional(Type.Number({ description: "WSMan operation timeout seconds" })),
			noProxy: Type.Optional(Type.Boolean({ description: "Ignore proxy environment variables" })),
		}),

		async execute(_toolCallId, params: WinrmParams, signal, _onUpdate, ctx) {
			const helper = findHelper(ctx.cwd);
			if (!existsSync(helper)) {
				throw new Error(`WinRM helper not found at ${helper}`);
			}

			const args = [helper, ...buildArgs(params)];
			const result = await runProcess("python3", args, ctx.cwd, signal);
			const combined = `${result.stdout}${result.stderr ? `${result.stdout ? "\n" : ""}[stderr]\n${result.stderr}` : ""}`.trimEnd();
			const { text, fullOutputPath } = await formatOutput(combined || "(no output)");

			if (signal?.aborted) {
				return {
					content: [{ type: "text", text: `WinRM ${params.action} cancelled.` }],
					details: { action: params.action, cancelled: true },
				};
			}

			if (result.exitCode !== 0) {
				throw new Error(`WinRM ${params.action} failed with exit code ${result.exitCode ?? `signal ${result.signal}`}\n${text}`);
			}

			return {
				content: [{ type: "text", text }],
				details: {
					action: params.action,
					exitCode: result.exitCode,
					fullOutputPath,
				},
			};
		},
	});
}
