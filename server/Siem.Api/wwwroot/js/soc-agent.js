(() => {
    const root = document.querySelector('[data-soc-agent-workspace]');
    if (!root || !window.fetch) {
        return;
    }

    const form = document.getElementById('soc-agent-composer');
    const textarea = document.getElementById('Message');
    const contextInput = document.getElementById('ComposerContextAgentId');
    const hiddenSessionInput = document.getElementById('soc-agent-session-id-input');
    const sendButton = document.getElementById('soc-agent-send-button');
    const cancelButton = document.getElementById('soc-agent-cancel-button');
    const messageList = document.getElementById('soc-agent-message-list');
    const threadScroll = document.getElementById('soc-agent-thread-scroll');
    const threadEnd = document.getElementById('soc-agent-thread-end');
    const emptyState = document.getElementById('soc-agent-empty');
    const scrollButton = document.getElementById('soc-agent-scroll-bottom');
    const runState = document.getElementById('soc-agent-run-state');
    const alertBox = document.getElementById('soc-agent-live-alert');
    const banner = document.getElementById('soc-agent-connection-banner');
    const activityList = document.getElementById('soc-agent-activity-list');
    const activityEmpty = document.getElementById('soc-agent-activity-empty');
    const charCount = document.getElementById('soc-agent-char-count');
    const contextChip = document.getElementById('soc-agent-context-chip');
    const sessionMeta = document.getElementById('soc-agent-session-meta');
    const providerInlineNotice = document.getElementById('soc-agent-provider-inline-notice');
    const providerStatus = document.getElementById('soc-agent-provider-inline-status');
    const providerPill = document.getElementById('soc-agent-provider-pill');
    const providerName = document.getElementById('soc-agent-provider-inline-name');
    const providerMessage = document.getElementById('soc-agent-provider-inline-message');
    const toggleActivity = document.getElementById('soc-agent-toggle-activity');
    const workspace = document.querySelector('.soc-agent-workspace');
    const maxLength = Number(root.dataset.maxMessageLength || '4000');
    let currentSessionId = root.dataset.sessionId || '';
    let currentRunId = null;
    let eventSource = null;
    let reconnectTimer = null;
    let lastSequence = 0;
    let running = false;
    let autoFollow = false;
    let followScrollFrame = null;
    let programmaticScrollUntil = 0;
    let pendingAssistant = null;
    let pendingAssistantContent = '';

    function showAlert(message, kind = 'notice') {
        if (!alertBox) return;
        alertBox.textContent = message;
        alertBox.hidden = false;
        alertBox.className = kind === 'error' ? 'alert live-alert' : 'notice live-alert';
    }

    function hideAlert() {
        if (alertBox) {
            alertBox.hidden = true;
            alertBox.textContent = '';
        }
    }

    function setBanner(message, isError = false) {
        if (!banner) return;
        banner.hidden = !message;
        banner.textContent = message || '';
        banner.classList.toggle('error', Boolean(isError));
    }

    function setRunning(isRunning, label) {
        running = isRunning;
        runState.textContent = label || (isRunning ? 'Running' : 'Idle');
        runState.classList.toggle('warning', isRunning);
        sendButton.disabled = isRunning;
        cancelButton.disabled = !isRunning || !currentRunId;
        textarea.setAttribute('aria-busy', isRunning ? 'true' : 'false');
    }

    function updateCharacterCount() {
        const length = textarea.value.length;
        charCount.textContent = `${length} / ${maxLength}`;
        charCount.classList.toggle('danger-text', length > maxLength * 0.95);
        textarea.style.height = 'auto';
        textarea.style.height = `${Math.min(textarea.scrollHeight, 220)}px`;
    }

    function updateContextChip() {
        const value = (contextInput.value || '').trim();
        contextChip.textContent = value ? `Agent context: ${value}` : 'Global SIEM context';
    }

    function hasThreadContent() {
        return Boolean(messageList && messageList.children.length > 0);
    }

    function latestThreadTarget() {
        return threadEnd || messageList?.lastElementChild || messageList || threadScroll;
    }

    function latestViewportBottom() {
        const composerTop = form.getBoundingClientRect().top;
        if (composerTop > 0 && composerTop < window.innerHeight) {
            return Math.max(0, composerTop - 16);
        }

        return window.innerHeight - 16;
    }

    function isLatestVisible() {
        const target = latestThreadTarget();
        if (!target || !hasThreadContent()) {
            return true;
        }

        const rect = target.getBoundingClientRect();
        return rect.bottom >= -64 && rect.bottom <= latestViewportBottom() + 96;
    }

    function updateScrollControl() {
        const nearLatest = isLatestVisible();
        const showControl = hasThreadContent() && (!autoFollow || !nearLatest);
        scrollButton.hidden = !showControl;
        scrollButton.disabled = !showControl;
        scrollButton.setAttribute('aria-disabled', String(!showControl));
    }

    function setAutoFollow(shouldFollow) {
        autoFollow = shouldFollow;
        updateScrollControl();
    }

    function latestScrollTop(target) {
        const rect = target.getBoundingClientRect();
        const desired = window.scrollY + rect.bottom - latestViewportBottom();
        return Math.max(0, Math.ceil(desired));
    }

    function performScrollToLatest(force = false) {
        if (force) {
            autoFollow = true;
        }

        const target = latestThreadTarget();
        if ((force || autoFollow) && target) {
            programmaticScrollUntil = Date.now() + (force ? 700 : 250);
            window.scrollTo({
                top: latestScrollTop(target),
                behavior: force ? 'smooth' : 'auto'
            });
            window.requestAnimationFrame(updateScrollControl);
            return;
        }

        updateScrollControl();
    }

    function scrollToLatest(force = false) {
        if (force) {
            autoFollow = true;
        }

        if (followScrollFrame) {
            window.cancelAnimationFrame(followScrollFrame);
        }

        followScrollFrame = window.requestAnimationFrame(() => {
            followScrollFrame = window.requestAnimationFrame(() => {
                followScrollFrame = null;
                performScrollToLatest(force);
            });
        });
    }

    function markUserScrollIntent() {
        programmaticScrollUntil = 0;
    }

    function createElement(tag, className, text) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text !== undefined && text !== null) element.textContent = text;
        return element;
    }

    function roleLabel(role) {
        return role === 'operator' ? 'Operator' : 'soc-agent';
    }

    function safeUrl(url, allowExternal = false) {
        const value = String(url || '').trim();
        if (!value || value.startsWith('//') || /[\u0000-\u001f\u007f]/.test(value)) {
            return '#';
        }

        try {
            const parsed = new URL(value, window.location.origin);
            const hasExplicitScheme = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(value);
            if (parsed.origin === window.location.origin && parsed.pathname.startsWith('/') && (!hasExplicitScheme || parsed.protocol === window.location.protocol)) {
                return `${parsed.pathname}${parsed.search}${parsed.hash}`;
            }

            if (allowExternal
                && (parsed.protocol === 'https:' || parsed.protocol === 'http:')
                && !parsed.username
                && !parsed.password) {
                return parsed.href;
            }
        } catch (_) {
            // Fall through to inert link.
        }
        return '#';
    }

    function sanitizeMarkdownLink(url) {
        const href = safeUrl(url, true);
        return href === '#' ? null : href;
    }

    function isExternalHref(href) {
        try {
            const parsed = new URL(href, window.location.origin);
            return parsed.origin !== window.location.origin && (parsed.protocol === 'https:' || parsed.protocol === 'http:');
        } catch (_) {
            return false;
        }
    }

    function shouldRenderMarkdown(role) {
        return role !== 'operator';
    }

    function hydratePersistedMarkdownMessages() {
        document.querySelectorAll('[data-message-markdown="true"]').forEach(element => {
            renderMarkdownInto(element, element.textContent || '');
        });
    }

    function createMessageBox(role, content) {
        if (!shouldRenderMarkdown(role)) {
            return createElement('pre', 'message-box', content || '');
        }

        const element = createElement('div', 'message-box markdown-content');
        element.dataset.messageMarkdown = 'true';
        renderMarkdownInto(element, content || '');
        return element;
    }

    function updateMessageContent(item, role, content) {
        const box = item?.querySelector('.message-box');
        if (!box) return;

        if (box.dataset.messageMarkdown === 'true' || shouldRenderMarkdown(role || item.dataset.role)) {
            if (box.dataset.messageMarkdown !== 'true') {
                box.dataset.messageMarkdown = 'true';
                box.classList.add('markdown-content');
            }
            renderMarkdownInto(box, content || '');
            return;
        }

        box.textContent = content || '';
    }

    function currentMessageText(item) {
        return item?.querySelector('.message-box')?.textContent || '';
    }

    function isFenceClose(line, fenceCharacter, minimumLength) {
        const trimmed = line.trim();
        if (trimmed.length < minimumLength) return false;
        for (const character of trimmed) {
            if (character !== fenceCharacter) return false;
        }
        return true;
    }

    function parseListMarker(line) {
        const unordered = line.match(/^\s{0,3}[-*+]\s+(.+)$/);
        if (unordered) {
            return { ordered: false, text: unordered[1] };
        }

        const ordered = line.match(/^\s{0,3}\d+[.)]\s+(.+)$/);
        if (ordered) {
            return { ordered: true, text: ordered[1] };
        }

        return null;
    }

    function isMarkdownBlockStart(line) {
        return /^\s*(```+|~~~+)/.test(line)
            || /^#{1,3}\s+/.test(line)
            || /^\s{0,3}>/.test(line)
            || Boolean(parseListMarker(line));
    }

    function renderMarkdownInto(container, markdown) {
        container.textContent = '';
        const source = String(markdown || '').replace(/\r\n?/g, '\n');
        if (!source.trim()) {
            return;
        }

        const lines = source.split('\n');
        let index = 0;

        while (index < lines.length) {
            const line = lines[index];
            if (!line.trim()) {
                index += 1;
                continue;
            }

            const fence = line.match(/^\s*(```+|~~~+)\s*([A-Za-z0-9_-]+)?\s*$/);
            if (fence) {
                const fenceToken = fence[1];
                const codeLines = [];
                index += 1;
                while (index < lines.length && !isFenceClose(lines[index], fenceToken[0], fenceToken.length)) {
                    codeLines.push(lines[index]);
                    index += 1;
                }
                if (index < lines.length) {
                    index += 1;
                }

                const pre = createElement('pre', 'markdown-code-block');
                const code = createElement('code', '', codeLines.join('\n'));
                pre.appendChild(code);
                container.appendChild(pre);
                continue;
            }

            const heading = line.match(/^(#{1,3})\s+(.+?)\s*#*\s*$/);
            if (heading) {
                const level = heading[1].length + 2;
                const element = createElement(`h${level}`, '');
                renderInlineInto(element, heading[2]);
                container.appendChild(element);
                index += 1;
                continue;
            }

            if (/^\s{0,3}>/.test(line)) {
                const quoteLines = [];
                while (index < lines.length && /^\s{0,3}>/.test(lines[index])) {
                    quoteLines.push(lines[index].replace(/^\s{0,3}>\s?/, ''));
                    index += 1;
                }
                const quote = createElement('blockquote');
                const paragraph = createElement('p');
                renderInlineInto(paragraph, quoteLines.join('\n'));
                quote.appendChild(paragraph);
                container.appendChild(quote);
                continue;
            }

            const firstListMarker = parseListMarker(line);
            if (firstListMarker) {
                const list = createElement(firstListMarker.ordered ? 'ol' : 'ul');
                while (index < lines.length) {
                    const marker = parseListMarker(lines[index]);
                    if (!marker || marker.ordered !== firstListMarker.ordered) {
                        break;
                    }
                    const item = createElement('li');
                    renderInlineInto(item, marker.text);
                    list.appendChild(item);
                    index += 1;
                }
                container.appendChild(list);
                continue;
            }

            const paragraphLines = [];
            while (index < lines.length && lines[index].trim() && !isMarkdownBlockStart(lines[index])) {
                paragraphLines.push(lines[index]);
                index += 1;
            }
            const paragraph = createElement('p');
            renderInlineInto(paragraph, paragraphLines.join('\n'));
            container.appendChild(paragraph);
        }
    }

    function renderInlineInto(parent, text, options = {}) {
        const allowLinks = options.allowLinks !== false;
        let index = 0;
        let buffer = '';
        const value = String(text || '');

        function flushText() {
            if (buffer) {
                parent.appendChild(document.createTextNode(buffer));
                buffer = '';
            }
        }

        while (index < value.length) {
            if (value[index] === '\n') {
                flushText();
                parent.appendChild(document.createElement('br'));
                index += 1;
                continue;
            }

            if (value.startsWith('![', index)) {
                const image = parseMarkdownLink(value, index + 1);
                if (image) {
                    buffer += value.slice(index, image.end);
                    index = image.end;
                    continue;
                }
            }

            if (value[index] === '`') {
                const close = value.indexOf('`', index + 1);
                if (close > index + 1) {
                    flushText();
                    parent.appendChild(createElement('code', '', value.slice(index + 1, close)));
                    index = close + 1;
                    continue;
                }
            }

            if (allowLinks && value[index] === '[') {
                const link = parseMarkdownLink(value, index);
                if (link) {
                    flushText();
                    const href = sanitizeMarkdownLink(link.url);
                    if (href) {
                        const anchor = createElement('a');
                        anchor.href = href;
                        if (isExternalHref(href)) {
                            anchor.target = '_blank';
                            anchor.rel = 'noreferrer noopener';
                        }
                        renderInlineInto(anchor, link.label, { allowLinks: false });
                        parent.appendChild(anchor);
                    } else {
                        parent.appendChild(document.createTextNode(link.label || link.url));
                    }
                    index = link.end;
                    continue;
                }
            }

            const strongMarker = value.startsWith('**', index) ? '**' : (value.startsWith('__', index) ? '__' : null);
            if (strongMarker) {
                const close = value.indexOf(strongMarker, index + strongMarker.length);
                if (close > index + strongMarker.length) {
                    flushText();
                    const strong = createElement('strong');
                    renderInlineInto(strong, value.slice(index + strongMarker.length, close), { allowLinks });
                    parent.appendChild(strong);
                    index = close + strongMarker.length;
                    continue;
                }
            }

            const emphasisMarker = (value[index] === '*' && value[index + 1] !== '*')
                ? '*'
                : ((value[index] === '_' && value[index + 1] !== '_') ? '_' : null);
            if (emphasisMarker) {
                const close = value.indexOf(emphasisMarker, index + 1);
                if (close > index + 1) {
                    flushText();
                    const emphasis = createElement('em');
                    renderInlineInto(emphasis, value.slice(index + 1, close), { allowLinks });
                    parent.appendChild(emphasis);
                    index = close + 1;
                    continue;
                }
            }

            buffer += value[index];
            index += 1;
        }

        flushText();
    }

    function parseMarkdownLink(value, start) {
        const labelEnd = value.indexOf(']', start + 1);
        if (labelEnd <= start + 1 || value[labelEnd + 1] !== '(') {
            return null;
        }

        const urlEnd = value.indexOf(')', labelEnd + 2);
        if (urlEnd <= labelEnd + 2) {
            return null;
        }

        const label = value.slice(start + 1, labelEnd);
        const url = value.slice(labelEnd + 2, urlEnd).trim();
        if (!label.trim() || !url) {
            return null;
        }

        return { label, url, end: urlEnd + 1 };
    }

    function appendMessage(message) {
        if (!message || !message.message_id) return;
        const existing = document.getElementById(`message-${message.message_id}`);
        if (existing) return existing;

        emptyState.hidden = true;

        let item;
        if (pendingAssistant && message.role !== 'operator') {
            item = pendingAssistant;
            item.classList.remove('pending');
            item.removeAttribute('aria-busy');
            item.id = `message-${message.message_id}`;
            item.dataset.messageId = message.message_id;
            item.dataset.role = message.role;
            updateMessageContent(item, message.role, message.content || pendingAssistantContent);
            pendingAssistant = null;
            pendingAssistantContent = '';
            const meta = item.querySelector('.message-meta');
            meta.textContent = '';
            hydrateMessageMeta(meta, message);
            const existingTools = item.querySelector('.tool-card-grid');
            if (existingTools) existingTools.remove();
            const existingCitations = item.querySelector('.citations');
            if (existingCitations) existingCitations.remove();
            hydrateToolCards(item, message.tool_runs || []);
            hydrateCitations(item, message.citations || []);
        } else {
            item = createElement('li', `message-bubble ${message.role === 'operator' ? 'operator' : 'assistant'}`);
            item.id = `message-${message.message_id}`;
            item.dataset.messageId = message.message_id;
            item.dataset.role = message.role;
            const meta = createElement('div', 'message-meta');
            hydrateMessageMeta(meta, message);
            item.appendChild(meta);
            item.appendChild(createMessageBox(message.role, message.content || ''));
            hydrateToolCards(item, message.tool_runs || []);
            hydrateCitations(item, message.citations || []);
            messageList.appendChild(item);
        }

        scrollToLatest();
        return item;
    }

    function appendOptimisticOperatorMessage(content) {
        emptyState.hidden = true;
        const item = createElement('li', 'message-bubble operator sending');
        item.id = `message-pending-operator-${Date.now()}`;
        item.dataset.role = 'operator';
        const meta = createElement('div', 'message-meta');
        meta.appendChild(createElement('strong', '', 'Operator'));
        meta.appendChild(createElement('span', 'badge warning', 'sending'));
        item.appendChild(meta);
        item.appendChild(createMessageBox('operator', content));
        messageList.appendChild(item);
        scrollToLatest();
        return item;
    }

    function hydrateOptimisticOperatorMessage(item, message) {
        if (!item || !message?.message_id) return;
        item.classList.remove('sending');
        item.id = `message-${message.message_id}`;
        item.dataset.messageId = message.message_id;
        const meta = item.querySelector('.message-meta');
        meta.textContent = '';
        hydrateMessageMeta(meta, message);
        updateMessageContent(item, message.role, message.content || currentMessageText(item));
    }

    function removeOptimisticOperatorMessage(item) {
        if (item?.classList.contains('sending')) {
            item.remove();
            emptyState.hidden = hasThreadContent();
        }
    }

    function hydrateMessageMeta(meta, message) {
        meta.appendChild(createElement('strong', '', roleLabel(message.role)));
        meta.appendChild(createElement('span', '', new Date(message.created_at || Date.now()).toLocaleString()));
        if (message.provider) {
            meta.appendChild(createElement('span', 'badge', `${message.provider} / ${message.model || ''}`));
        }
        if (message.error_code) {
            meta.appendChild(createElement('span', 'badge danger', message.error_code));
        }
    }

    function hydrateToolCards(container, tools) {
        if (!tools.length) return;
        const grid = createElement('div', 'tool-card-grid');
        grid.setAttribute('aria-label', 'Tool activity for this message');
        for (const tool of tools) {
            const card = createElement('article', 'tool-card complete');
            const header = createElement('div', 'tool-card-header');
            header.appendChild(createElement('strong', '', tool.tool_name || 'tool'));
            header.appendChild(createElement('span', 'badge ok', 'ok'));
            card.appendChild(header);
            card.appendChild(createElement('p', '', tool.summary || 'Completed.'));
            card.appendChild(createElement('p', 'muted', `Rows: ${tool.row_count ?? 0}`));
            grid.appendChild(card);
        }
        container.appendChild(grid);
    }

    function hydrateCitations(container, citations) {
        if (!citations.length) return;
        const wrapper = createElement('div', 'citations');
        wrapper.appendChild(createElement('h3', '', 'Citations'));
        const list = createElement('ul');
        for (const citation of citations) {
            const item = createElement('li');
            const link = createElement('a', '', citation.label || 'Citation');
            link.href = safeUrl(citation.url);
            item.appendChild(link);
            item.appendChild(document.createTextNode(' '));
            item.appendChild(createElement('span', 'muted', citation.kind || 'reference'));
            list.appendChild(item);
        }
        wrapper.appendChild(list);
        container.appendChild(wrapper);
    }

    function ensurePendingAssistant() {
        if (pendingAssistant) return pendingAssistant;
        emptyState.hidden = true;
        pendingAssistant = createElement('li', 'message-bubble assistant pending', '');
        pendingAssistant.id = `message-pending-${currentRunId || 'run'}`;
        pendingAssistant.setAttribute('aria-busy', 'true');
        const meta = createElement('div', 'message-meta');
        meta.appendChild(createElement('strong', '', 'soc-agent'));
        meta.appendChild(createElement('span', 'badge warning', 'streaming'));
        pendingAssistant.appendChild(meta);
        pendingAssistant.appendChild(createMessageBox('soc_agent', 'Preparing live response…'));
        messageList.appendChild(pendingAssistant);
        return pendingAssistant;
    }

    function setPendingAssistantPlaceholder(message) {
        const item = ensurePendingAssistant();
        if (!pendingAssistantContent) {
            updateMessageContent(item, 'soc_agent', message);
        }
        scrollToLatest();
    }

    function removePendingAssistantIfEmpty() {
        if (pendingAssistant && !pendingAssistantContent) {
            pendingAssistant.remove();
            pendingAssistant = null;
            emptyState.hidden = hasThreadContent();
        }
    }

    function appendContentDelta(delta) {
        const item = ensurePendingAssistant();
        pendingAssistantContent += delta || '';
        updateMessageContent(item, 'soc_agent', pendingAssistantContent);
        scrollToLatest();
    }

    function upsertActivity(type, data, sequence) {
        if (!activityList) return;
        activityEmpty.hidden = true;
        const toolName = data.tool_name || data.tool_run?.tool_name || 'soc-agent';
        let card = activityList.querySelector(`[data-tool-name="${CSS.escape(toolName)}"].running`);
        if (!card) {
            card = createElement('article', 'activity-card running');
            card.dataset.toolName = toolName;
            const header = createElement('div', 'tool-card-header');
            header.appendChild(createElement('strong', '', toolName));
            header.appendChild(createElement('span', 'badge warning', 'running'));
            card.appendChild(header);
            card.appendChild(createElement('p', '', data.summary || 'Running.'));
            card.appendChild(createElement('p', 'muted', `seq ${sequence}`));
            activityList.prepend(card);
        }

        if (type === 'tool_finished') {
            card.classList.remove('running');
            card.classList.add('complete');
            const badge = card.querySelector('.badge');
            badge.className = 'badge ok';
            badge.textContent = 'ok';
            card.querySelector('p').textContent = data.summary || 'Completed.';
            card.querySelector('.muted').textContent = `Rows: ${data.row_count ?? 0} · seq ${sequence}`;
        }
    }

    function providerNeedsAttention(status) {
        if (!status) return false;
        if (status.requires_connection) return true;
        return ['disabled', 'provider_not_configured', 'auth_required', 'expired', 'refresh_failed', 'unsupported_delegated_auth', 'unsupported_subscription_oauth', 'scope_missing', 'plan_limited', 'budget_limited', 'rate_limited', 'provider_error'].includes(status.status || '');
    }

    function updateProvider(status) {
        if (!status) return;
        const statusText = status.status || 'unknown';
        if (providerStatus) providerStatus.textContent = statusText;
        if (providerPill) {
            providerPill.textContent = statusText;
            providerPill.setAttribute('aria-label', `Provider status: ${statusText}`);
            providerPill.setAttribute('title', status.display_name || status.provider || 'Provider');
        }
        if (providerName) providerName.textContent = status.display_name || status.provider || 'Provider';
        if (providerMessage) providerMessage.textContent = status.message || '';
        if (providerInlineNotice) {
            providerInlineNotice.hidden = !providerNeedsAttention(status);
        }
    }

    function applyLiveEvent(rawEvent) {
        const payload = JSON.parse(rawEvent.data);
        const type = payload.type || rawEvent.type;
        lastSequence = Math.max(lastSequence, Number(payload.sequence || 0));
        const data = payload.data || {};

        switch (type) {
            case 'resume_snapshot':
                setBanner(data.status === 'running' || data.status === 'cancel_requested' ? 'Reconnected to an active soc-agent run.' : 'Connected to soc-agent live events.');
                break;
            case 'session_created':
                if (data.session?.session_id) {
                    currentSessionId = data.session.session_id;
                    root.dataset.sessionId = currentSessionId;
                    hiddenSessionInput.value = currentSessionId;
                    sessionMeta.textContent = `Session ${currentSessionId} · live run active`;
                    const url = new URL(window.location.href);
                    url.searchParams.set('session_id', currentSessionId);
                    window.history.replaceState({}, '', url);
                }
                break;
            case 'message_created':
                appendMessage(data.message);
                break;
            case 'run_started':
                setRunning(true, 'Running');
                setPendingAssistantPlaceholder('soc-agent is running SIEM tools…');
                showAlert(data.message || 'soc-agent run started.');
                break;
            case 'provider_status':
                updateProvider(data.provider_status);
                if (data.provider_status?.data_may_leave_local_siem && !data.provider_status?.requires_connection) {
                    setPendingAssistantPlaceholder('Using the configured external provider after local SIEM tool context is bounded and redacted…');
                }
                break;
            case 'tool_started':
                setPendingAssistantPlaceholder(data.summary || `Running ${data.tool_name || 'soc-agent tool'}…`);
                upsertActivity(type, data, payload.sequence);
                break;
            case 'tool_finished':
                upsertActivity(type, data, payload.sequence);
                break;
            case 'citation_added':
                // Final persisted assistant messages render citations; live citation events keep the stream resumable.
                break;
            case 'content_delta':
                appendContentDelta(data.delta || '');
                break;
            case 'run_cancel_requested':
                setRunning(true, 'Cancelling');
                setPendingAssistantPlaceholder(data.message || 'Cancellation requested…');
                showAlert(data.message || 'Cancellation requested.');
                break;
            case 'run_error':
                setPendingAssistantPlaceholder(data.message || 'soc-agent run reported an error.');
                showAlert(data.message || 'soc-agent run reported an error.', 'error');
                setBanner(data.message || 'soc-agent run reported an error.', true);
                break;
            case 'run_complete':
                setRunning(false, data.status === 'cancelled' ? 'Cancelled' : (data.status === 'error' ? 'Error' : 'Complete'));
                currentRunId = null;
                if (eventSource) {
                    eventSource.close();
                    eventSource = null;
                }
                if (reconnectTimer) {
                    window.clearTimeout(reconnectTimer);
                    reconnectTimer = null;
                }
                if (pendingAssistant && !pendingAssistantContent && data.assistant_message) {
                    appendMessage(data.assistant_message);
                } else if (pendingAssistant && !pendingAssistantContent) {
                    pendingAssistant.classList.remove('pending');
                    pendingAssistant.removeAttribute('aria-busy');
                    updateMessageContent(pendingAssistant, 'soc_agent', data.status === 'complete'
                        ? 'soc-agent completed. Refresh if the final response is not shown.'
                        : currentMessageText(pendingAssistant));
                }
                setBanner('soc-agent run complete.');
                if (data.status === 'complete') hideAlert();
                break;
        }
    }

    function openEventStream(runId, after = 0) {
        if (eventSource) eventSource.close();
        currentRunId = runId;
        const url = `/soc-agent/live/runs/${encodeURIComponent(runId)}/events?after=${encodeURIComponent(after)}`;
        eventSource = new EventSource(url, { withCredentials: true });
        setBanner('Connecting to soc-agent live stream…');
        const eventTypes = ['resume_snapshot', 'session_created', 'message_created', 'run_started', 'provider_status', 'tool_started', 'tool_finished', 'citation_added', 'content_delta', 'run_cancel_requested', 'run_error', 'run_complete'];
        for (const type of eventTypes) {
            eventSource.addEventListener(type, applyLiveEvent);
        }
        eventSource.onopen = () => setBanner('Live stream connected.');
        eventSource.onerror = () => {
            if (running && currentRunId) {
                setBanner('Live stream reconnecting…', false);
                eventSource.close();
                if (reconnectTimer) window.clearTimeout(reconnectTimer);
                reconnectTimer = window.setTimeout(() => openEventStream(currentRunId, lastSequence), 1000);
            }
        };
    }

    async function startRun(event) {
        event.preventDefault();
        hideAlert();
        const message = textarea.value.trim();
        if (!message || message.length > maxLength || running) {
            showAlert(`Enter a message up to ${maxLength} characters.`, 'error');
            return;
        }

        setRunning(true, 'Starting');
        setBanner('Starting soc-agent run…');
        setAutoFollow(true);
        const optimisticOperator = appendOptimisticOperatorMessage(message);
        setPendingAssistantPlaceholder('Starting soc-agent live run…');
        textarea.value = '';
        updateCharacterCount();
        try {
            const response = await fetch(root.dataset.liveStartUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: currentSessionId || null,
                    message,
                    context_agent_id: (contextInput.value || '').trim() || null
                })
            });

            if (!response.ok) {
                const problem = await response.text();
                throw new Error(problem || `soc-agent live start failed with ${response.status}`);
            }

            const result = await response.json();
            currentSessionId = result.session?.session_id || currentSessionId;
            hiddenSessionInput.value = currentSessionId;
            root.dataset.sessionId = currentSessionId;
            if (currentSessionId) {
                sessionMeta.textContent = `Session ${currentSessionId} · live run active`;
                const url = new URL(window.location.href);
                url.searchParams.set('session_id', currentSessionId);
                url.searchParams.delete('agent_id');
                window.history.replaceState({}, '', url);
            }
            hydrateOptimisticOperatorMessage(optimisticOperator, result.user_message);
            setPendingAssistantPlaceholder('soc-agent is running SIEM tools…');
            openEventStream(result.run_id, 0);
            setRunning(true, 'Running');
        } catch (error) {
            removeOptimisticOperatorMessage(optimisticOperator);
            removePendingAssistantIfEmpty();
            textarea.value = message;
            updateCharacterCount();
            setRunning(false, 'Idle');
            showAlert('soc-agent live run could not start. Use the form fallback or confirm your operator session is still signed in.', 'error');
            setBanner(error.message, true);
        }
    }

    async function cancelRun() {
        if (!currentRunId) return;
        cancelButton.disabled = true;
        setRunning(true, 'Cancelling');
        try {
            await fetch(`/soc-agent/live/runs/${encodeURIComponent(currentRunId)}/cancel`, {
                method: 'POST',
                credentials: 'same-origin'
            });
        } catch (_) {
            showAlert('Cancellation could not be sent; reconnecting may recover the run state.', 'error');
        }
    }

    async function resumeActiveRun() {
        if (!currentSessionId) return;
        try {
            const response = await fetch(`/soc-agent/live/sessions/${encodeURIComponent(currentSessionId)}/active`, { credentials: 'same-origin' });
            if (!response.ok) return;
            const active = await response.json();
            if (active.has_active_run && active.run_id) {
                setAutoFollow(true);
                setRunning(true, active.status === 'cancel_requested' ? 'Cancelling' : 'Running');
                scrollToLatest();
                openEventStream(active.run_id, 0);
            }
        } catch (_) {
            setBanner('Could not check for an active soc-agent run.', true);
        }
    }

    form.addEventListener('submit', startRun);
    cancelButton.addEventListener('click', cancelRun);
    textarea.addEventListener('input', updateCharacterCount);
    contextInput.addEventListener('input', updateContextChip);
    textarea.addEventListener('keydown', event => {
        const explicitSendShortcut = event.ctrlKey || event.metaKey;
        const plainEnterSend = !event.shiftKey && !event.altKey && !event.ctrlKey && !event.metaKey;
        if (event.key === 'Enter' && !event.shiftKey && (plainEnterSend || explicitSendShortcut)) {
            event.preventDefault();
            if (!running && !sendButton.disabled) {
                form.requestSubmit();
            }
        }
    });
    window.addEventListener('scroll', () => {
        if (Date.now() < programmaticScrollUntil) {
            window.requestAnimationFrame(updateScrollControl);
            return;
        }

        setAutoFollow(isLatestVisible());
    }, { passive: true });
    window.addEventListener('wheel', markUserScrollIntent, { passive: true });
    window.addEventListener('touchmove', markUserScrollIntent, { passive: true });
    window.addEventListener('keydown', event => {
        if (['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End', 'Space'].includes(event.code)) {
            markUserScrollIntent();
        }
    });
    window.addEventListener('resize', () => {
        if (autoFollow) {
            scrollToLatest();
        } else {
            updateScrollControl();
        }
    }, { passive: true });
    scrollButton.addEventListener('click', () => scrollToLatest(true));
    document.querySelectorAll('[data-prompt]').forEach(button => {
        button.addEventListener('click', () => {
            textarea.value = button.dataset.prompt || '';
            updateCharacterCount();
            textarea.focus();
        });
    });
    toggleActivity.addEventListener('click', () => {
        const collapsed = workspace.classList.toggle('activity-collapsed');
        toggleActivity.setAttribute('aria-expanded', String(!collapsed));
        toggleActivity.textContent = collapsed ? 'Expand' : 'Collapse';
    });

    hydratePersistedMarkdownMessages();
    updateCharacterCount();
    updateContextChip();
    setAutoFollow(isLatestVisible());
    window.requestAnimationFrame(updateScrollControl);
    resumeActiveRun();
})();
