import { APIError, request } from './api.js';

const navigation = document.querySelector('#navigation');
const account = document.querySelector('#account');
const domainStatus = document.querySelector('#domain-status');
const layout = document.querySelector('#layout');
const view = document.querySelector('#view');
const notice = document.querySelector('#notice');
const state = { session: null, epoch: 0, poll: null, messages: [] };
const maxChatMessageLength = 4000;
const maxDraftDescriptionLength = 512;
const roleLabel = { ADMIN: '域管理员', BUYER: '采购员', AUDITOR: '审计员' };
const modeLabels = { RESOURCE_PREAUTHORIZED: 'RP / 供应商授权', BUYER_MANDATE: 'BM / 采购权威授权' };
const statusLabel = {
  accepted: '已受理', pending: '已受理, 等待确认', waiting: '处理中', confirmed: '已确认',
  delivered: '已交付', failed: '失败', denied: '网关拒绝', rejected: '网关拒绝',
  unknown: '业务结果未知', model_stopped: '模型已停止', completed: '已定案',
  finalized: '已定案', running: '执行中', paused: '已暂停', active: '有效',
  suspended: '已暂停', revoked: '已撤销', success: '成功', allowed: '已放行',
  preparing: '准备中', ready: '已就绪', stopped: '模型已停止', valid: '有效',
  submitted: '已提交', reconciled: '已核账', expired: '已过期', registered: '已登记',
  gateway_denied: '网关拒绝', outcome_unknown: '业务结果未知', decided: '已定案', deny: '网关拒绝', allow: '已放行',
  returned: '已返回',
};
const good = new Set(['confirmed', 'delivered', 'completed', 'finalized', 'success', 'allowed', 'allow', 'valid', 'reconciled', 'registered', 'decided']);
const bad = new Set(['failed', 'denied', 'rejected', 'revoked', 'expired', 'gateway_denied', 'deny']);
const wait = new Set(['accepted', 'pending', 'waiting', 'unknown', 'running', 'paused', 'suspended', 'preparing', 'submitted', 'outcome_unknown']);
const stageLabels = {
  REGISTER_TASK: '登记采购任务', DELIVER_G0: '签发及交付 G0', DELIVER_G1: '签发及交付 G1',
  EXECUTE: 'A1 转委托和 B1 执行', SuspendGrant: '暂停 G1', ResumeGrant: '恢复 G1',
};
const fieldLabels = {
  action: '动作', actionId: '意图 ID', actionStatus: '意图状态', amountMinor: '金额', appliedBlockHash: '采用区块哈希',
  appliedBlockNo: '采用块高', at: '时间', ancestor: '祖先委托', blockHash: '区块哈希',
  blockNumber: '块高', blockNo: '块高', callId: '工具调用 ID', code: '结果码',
  certificationDigest: '认证摘要', certificationId: '认证 ID', claim: '声明', claims: '声明',
  contextVersion: '环境版本', credentialId: '凭证 ID',
  decisionId: '决定 ID', decision: '决定', decisionAt: '定案时间', delegateDid: '受托者 DID', depth: '剩余深度',
  description: '任务说明', did: 'DID', disclosed: '实际披露', domain: '域声明', domainDid: '域 DID',
  domainId: '域', draftId: '草稿 ID', exp: '原委托截止', nbf: '生效时间',
  effectiveDeadline: '实际有效截止', environmentVersion: '环境版本', errorCode: '错误码',
  expiresAt: '截止时间', failedObjectId: '失败对象 ID', granteeDid: '受托者 DID', grantId: '委托 ID', grantPath: '授权路径',
  holderDid: '持有者 DID', id: '标识', invalidAncestor: '失效祖先',
  issuerDid: '签发者 DID', issuerKeyVersion: '签发者密钥版本', keyVersion: '密钥版本', kind: '主体类型',
  maxAmountMinor: '单笔上限', maxMinor: '单笔上限', mode: '授权模式', operationId: '操作 ID',
  orderId: '订单 ID', orders: '订单', quotes: '报价',
  outcome: '决定结果', parentId: '父委托 ID', pending: '待确认', policyDigest: '策略摘要',
  policyVersion: '策略版本', policyHash: '策略哈希',
  probeExpiresAt: '原探针期限', probeDeadline: '原探针期限', probeTxId: '原探针交易 txId', productId: '商品',
  purchasingAuthority: '采购权威', quantity: '数量', quoteId: '报价 ID',
  provider: '模型协议', requestedModel: '请求模型', responseModel: '返回模型',
  reasonCode: '决定原因码', reason: '原因', requestId: '请求 ID', remainingDepth: '剩余深度',
  result: '业务结果', revision: '版本', role: '角色', runId: '运行 ID', scope: '操作范围',
  rootDid: '根 DID', rootId: '根委托 ID', rootKeyVersion: '根密钥版本', settledAt: '定案时间', stage: '当前阶段',
  status: '状态', subjectDid: '主体 DID', subjectKeyVersion: '主体密钥版本',
  subjectId: '主体 DID', taskId: '任务 ID', tool: '工具', toolName: '工具', txId: '原交易 txId',
  totalAmountMinor: '总金额', unitPriceMinor: '单价', validUntil: '有效截止', value: '值',
  version: '版本', validationCode: '入块校验码',
};
const sections = [
  ['identity', '身份与信任'],
  ['disclosures', '凭证披露'],
  ['delegations', '委托树'],
  ['purchase', '采购任务'],
  ['decisions', '决策时间线'],
];

function element(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === false || value === null || value === undefined) continue;
    if (name.startsWith('on')) node.addEventListener(name.slice(2), value);
    else node.setAttribute(name, value === true ? '' : String(value));
  }
  node.append(...children.filter((child) => child !== null && child !== undefined));
  return node;
}

function label(text, input, hint) {
  return element('label', {}, text, input, hint ? element('small', {}, hint) : null);
}

function button(text, handler, secondary = false) {
  return element('button', { type: 'button', class: secondary ? 'secondary' : '', onclick: handler }, text);
}

function heading(title, text) {
  return element('header', { class: 'view-heading' },
    element('h1', { id: 'view-title' }, title),
    text ? element('p', { class: 'muted' }, text) : null);
}

function card(title, ...children) {
  return element('section', { class: 'card' }, title ? element('h2', {}, title) : null, ...children);
}

function setNotice(message = '', kind = 'info') {
  notice.hidden = !message;
  notice.dataset.kind = kind;
  notice.textContent = message;
}

function showError(error) {
  if (error instanceof APIError && error.status === 401 && state.session) {
    endSession();
  }
  const details = [error.code, error.requestId].filter(Boolean).join(' / ');
  const messages = {
    LOGIN_FAILED: '账号或密码无效.',
    DRAFT_VERSION_CONFLICT: '草稿版本已变化. 刷新页面后请重新核对并确认.',
  };
  setNotice([messages[error.code] || error.message, details].filter(Boolean).join(' - '), 'error');
}

function showDomain(domain, ready) {
  domainStatus.textContent = [domain ? domain + ' 域' : '本域', ready ? '已就绪' : '服务未就绪'].join(' / ');
  domainStatus.dataset.ready = Boolean(ready);
}

function route(name, id) {
  return '#' + name + (id ? '/' + encodeURIComponent(id) : '');
}

function currentRoute() {
  const [page, rawID] = location.hash.slice(1).split('/');
  try {
    return { page, id: rawID ? decodeURIComponent(rawID) : '' };
  } catch {
    return { page, id: '' };
  }
}

function navigate(page, id) {
  const target = route(page, id);
  if (location.hash === target) render();
  else location.hash = target;
}

function link(text, page, id, props) {
  return element('a', { href: route(page, id), ...props }, text);
}

function allowed(action) {
  return state.session?.actions?.includes(action);
}

function write(path, body, { method = 'POST', idempotencyKey } = {}) {
  return request(path, { method, body, csrf: state.session?.csrfToken, idempotencyKey });
}

function busy(button, action, reportError = showError) {
  return async (event) => {
    event.preventDefault();
    if (button.disabled) return;
    button.disabled = true;
    setNotice();
    try {
      await action(event);
    } catch (error) {
      reportError(error);
    } finally {
      button.disabled = false;
    }
  };
}

function status(value) {
  const key = String(value ?? '').toLowerCase().replaceAll('-', '_');
  return element('span', {
    class: 'pill', title: value,
    'data-tone': good.has(key) ? 'good' : bad.has(key) ? 'bad' : wait.has(key) ? 'wait' : '',
  }, statusLabel[key] ?? String(value ?? '待查询'));
}

function facts(rows) {
  const entries = rows.filter(([, value]) => value !== null && value !== undefined && value !== '');
  return element('dl', { class: 'facts' }, ...entries.map(([key, value]) =>
    element('div', {}, element('dt', {}, key), element('dd', {}, value))));
}

function saveKey(key, id) {
  sessionStorage.setItem(key, id);
  return id;
}

function retryKey(action, id, input) {
  const { domainId, subjectId } = state.session;
  const key = JSON.stringify(['workbench', domainId, subjectId, action, id, input]);
  return sessionStorage.getItem(key) || saveKey(key, crypto.randomUUID());
}

function showLogin() {
  const username = element('input', { name: 'username', required: true, autocomplete: 'username', maxlength: 64 });
  const password = element('input', { name: 'password', required: true, type: 'password', autocomplete: 'current-password' });
  const submit = element('button', { type: 'submit' }, '登录');
  const form = element('form', {
    class: 'stack',
    onsubmit: busy(submit, async () => {
      state.session = await request('/session/login', {
        method: 'POST',
        body: { username: username.value.trim(), password: password.value },
      });
      password.value = '';
      render();
    }),
  }, label('本域账号', username), label('密码', password), submit);
  view.append(heading('登录工作台'), card(null, form));
}

function endSession() {
  state.session = null;
  state.messages = [];
  if (location.hash !== '#login') history.replaceState(null, '', '#login');
  render();
}

function showAccount(active) {
  layout.classList.toggle('anonymous', !state.session);
  navigation.hidden = !state.session;
  navigation.replaceChildren();
  account.replaceChildren();
  if (!state.session) return;

  const links = [];
  if (allowed('managePurchasingAuthority')) links.push(['management', '本域管理']);
  if (allowed('procure')) links.push(['chat', '采购对话'], ['runs', '采购运行']);
  if (allowed('auditDecisions')) links.push(['decisions', '决策审计']);
  navigation.append(...links.map(([page, text]) =>
    link(text, page, undefined, { 'aria-current': active === page ? 'page' : null })));
  const logout = button('退出', null, true);
  logout.addEventListener('click', busy(logout, async () => {
    await write('/session/logout');
    endSession();
  }));
  account.append(
    element('span', { title: state.session.subjectId }, roleLabel[state.session.role] ?? state.session.role),
    logout,
  );
}

async function loadAuthority() {
  return request('/management/purchasing-authority');
}

function managementForm(authority, epoch) {
  const options = authority.eligibleServiceIds ?? [];
  const service = element('select', {},
    element('option', { value: '', disabled: true, selected: true }, '请选择资格操作'),
    ...options.map((id) => element('option', { value: id }, id)),
    authority.purchasingAuthority ? element('option', { value: 'clear' }, '清除采购权威') : null);
  if (options.includes(authority.purchasingAuthority)) service.value = authority.purchasingAuthority;
  const submit = element('button', { type: 'submit', disabled: !options.length && !authority.purchasingAuthority }, '提交资格操作');
  return card('PA 资格操作',
    facts([['本域', authority.domainId], ['当前采购权威', authority.purchasingAuthority || '未指定'], ['当前登记版本', authority.expectedRevision]]),
    element('form', {
      class: 'stack',
      onsubmit: busy(submit, async () => {
        if (!service.value) {
          setNotice('选择一个合资格的本域服务后提交.', 'error');
          return;
        }
        const body = {
          expectedRevision: authority.expectedRevision,
          purchasingAuthority: service.value === 'clear' ? null : service.value,
        };
        const idempotencyKey = retryKey('authority', authority.domainId, body);
        const result = await write('/management/purchasing-authority', body, { idempotencyKey });
        if (epoch === state.epoch) navigate('management', result.operationId);
      }),
    },
    label('采购权威服务', service, options.length ? '资格以当前登记判据为准.' : '当前没有合资格的本域服务.'),
    submit));
}

function operationCard(operation) {
  return card('原交易状态',
    status(operation.status),
    facts([
      ['操作 ID', element('code', {}, operation.operationId)],
      ['原交易 txId', operation.txId ? element('code', {}, operation.txId) : '等待分配'],
      ['登记方法', operation.method],
      ['交易阶段', operation.stage],
      ['入块校验码', operation.validationCode],
      ['块高', operation.validationCode ? operation.blockNumber : null],
      ['区块哈希', operation.blockHash ? element('code', {}, operation.blockHash) : null],
      ['提交失败码', operation.failureCode],
    ]));
}

function lookup(text, submitText, id, action) {
  const input = element('input', { name: 'id', required: true, value: id, autocapitalize: 'none', spellcheck: false });
  return element('form', {
    class: 'inline-lookup',
    onsubmit: (event) => {
      event.preventDefault();
      if (input.value.trim()) action(input.value.trim());
    },
  }, label(text, input), element('button', { type: 'submit' }, submitText));
}

async function showManagement(id, epoch) {
  view.append(heading('本域管理', '提交采购权威资格操作, 查询原交易及链上确认结果.'));
  const form = element('div');
  const transaction = element('div', { class: 'stack' },
    card('查询管理操作', lookup('操作 ID', '查询', id, (operationId) => navigate('management', operationId))));
  view.append(element('div', { class: 'split' }, form, transaction));
  let operationStatus = '';
  const operation = element('div');
  if (id) transaction.append(operation);

  const loadOperation = async () => {
    if (!id) return;
    const response = await request('/operations/' + encodeURIComponent(id));
    if (epoch !== state.epoch) return;
    operation.replaceChildren(operationCard(response));
    if (operationStatus === 'PENDING' && response.status === 'CONFIRMED') {
      const updated = await loadAuthority();
      if (epoch !== state.epoch) return;
      form.replaceChildren(managementForm(updated, epoch));
    }
    operationStatus = response.status;
  };
  const results = await Promise.allSettled([
    loadAuthority().then((data) => {
      if (epoch === state.epoch) form.replaceChildren(managementForm(data, epoch));
    }),
    loadOperation(),
  ]);
  if (epoch !== state.epoch) return;
  for (const item of results) if (item.status === 'rejected') showError(item.reason);
  if (operationStatus === 'PENDING') poll(epoch, loadOperation, () => operationStatus === 'PENDING');
}

function draftFields(draft) {
  const localDate = new Date(draft.expiresAt * 1000);
  const expiresAt = Number.isNaN(localDate.valueOf())
    ? ''
    : new Date(localDate.valueOf() - localDate.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
  const form = {
    productId: element('input', { value: draft.productId, required: true }),
    quantity: element('input', { type: 'number', value: draft.quantity, required: true, min: 1 }),
    mode: element('select', {}, ...Object.entries(modeLabels).map(([value, text]) => element('option', { value }, text))),
    maxAmountMinor: element('input', { type: 'number', value: draft.maxAmountMinor, required: true, min: 1 }),
    expiresAt: element('input', { type: 'datetime-local', value: expiresAt, required: true, step: 1 }),
    delegateDid: element('input', { value: draft.delegateDid, required: true, spellcheck: false }),
    description: element('textarea', { required: true }, draft.description ?? ''),
  };
  form.mode.value = draft.mode;
  return form;
}

function draftSummary(draft) {
  return facts([
    ['草稿版本', draft.version],
    ['商品', draft.productId],
    ['数量', draft.quantity],
    ['授权模式', modeLabels[draft.mode] ?? draft.mode],
    ['单笔上限', draft.maxAmountMinor == null ? null : (draft.maxAmountMinor / 100).toFixed(2) + ' 元'],
    ['截止时间', timestamp(draft.expiresAt)],
    ['受托者 DID', draft.delegateDid ? element('code', {}, draft.delegateDid) : null],
    ['任务说明', draft.description],
  ]);
}

function draftEditor(draft, epoch) {
  const fields = draftFields(draft);
  const save = element('button', { type: 'submit', class: 'secondary', disabled: true }, '保存修改');
  const confirm = button('确认并派单', null);
  const form = element('form', {
    class: 'stack',
    oninput: () => {
      save.disabled = false;
      confirm.disabled = true;
    },
  },
    element('p', { class: 'muted' }, '当前版本 ' + draft.version + '. 请核对草稿, 确认后开始正式采购流程.'),
    element('div', { class: 'grid' },
      label('商品编号', fields.productId),
      label('数量', fields.quantity),
      label('授权模式', fields.mode),
      label('单笔上限 (分)', fields.maxAmountMinor),
      label('截止时间 (本地时间)', fields.expiresAt)),
    label('受托者 DID', fields.delegateDid), label('任务说明', fields.description),
    element('div', { class: 'toolbar actions' }, save, confirm),
  );
  form.addEventListener('submit', busy(save, async () => {
    const description = fields.description.value.trim();
    if (!description || [...description].length > maxDraftDescriptionLength) {
      setNotice(`任务说明须为 1 至 ${maxDraftDescriptionLength} 个字符.`, 'error');
      return;
    }
    const body = {
      version: draft.version,
      productId: fields.productId.value.trim(),
      quantity: Number(fields.quantity.value),
      mode: fields.mode.value,
      maxAmountMinor: Number(fields.maxAmountMinor.value),
      expiresAt: Math.floor(new Date(fields.expiresAt.value).valueOf() / 1000),
      delegateDid: fields.delegateDid.value.trim(),
      description,
    };
    await write('/drafts/' + encodeURIComponent(draft.draftId), body, { method: 'PUT' });
    if (epoch === state.epoch) navigate('chat', draft.draftId);
  }));
  confirm.addEventListener('click', busy(confirm, async () => {
    const result = await write('/drafts/' + encodeURIComponent(draft.draftId) + '/confirm', { version: draft.version });
    if (epoch === state.epoch) {
      state.messages = [];
      navigate('runs', result.runId);
    }
  }));
  return card('采购草稿', form);
}

async function showChat(id, epoch) {
  const content = element('div', { class: 'stack' });
  const message = element('textarea', { name: 'message', required: true, placeholder: '请输入商品, 数量, 单笔上限和采购要求' });
  const send = element('button', { type: 'submit' }, '发送给 A1');
  const transcript = element('ol', { class: 'history', 'aria-label': '当前对话' },
    ...state.messages.map(({ text, author }) => element('li', {},
      element('strong', {}, author), element('br'), text)));
  const form = element('form', {
    class: 'stack',
    onsubmit: busy(send, async () => {
      const text = message.value.trim();
      if (!text) {
        setNotice('请输入采购需求.', 'error');
        return;
      }
      if ([...text].length > maxChatMessageLength) {
        setNotice(`采购需求最多 ${maxChatMessageLength} 个字符.`, 'error');
        return;
      }
      const body = id ? { message: text, draftId: id } : { message: text };
      const result = await write('/chat', body);
      if (epoch !== state.epoch) return;
      state.messages.push({ author: '采购员', text }, { author: 'A1', text: result.reply });
      navigate('chat', result.draft.draftId);
    }),
  }, label('采购需求', message), send);
  const chat = card('与 A1 对话', transcript, form);
  if (id) chat.append(link('新建对话', 'chat', null, {
    onclick: () => { state.messages = []; },
  }));
  view.append(heading('采购对话', '先与 A1 整理采购需求, 再核对并确认结构化草稿.'),
    element('div', { class: 'split' }, chat, content));
  if (id) {
    const draft = await request('/drafts/' + encodeURIComponent(id));
    if (epoch === state.epoch) content.append(draftEditor(draft, epoch));
  }
}

function timestamp(seconds) {
  if (!seconds) return null;
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.valueOf())) return String(seconds);
  return date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

function genericValue(value, key) {
  if (Array.isArray(value)) return value.length ? element('ul', { class: 'records' },
    ...value.map((entry) => element('li', {}, genericValue(entry, key)))) : '暂无记录';
  if (value && typeof value === 'object') {
    return facts(Object.entries(value).map(([name, item]) => [fieldLabels[name] ?? name, genericValue(item, name)]));
  }
  if (value === false || value === true) return value ? '是' : '否';
  if (value === null || value === undefined || value === '') return null;
  if (key === 'status' || key === 'outcome') return status(value);
  if (key === 'mode') return modeLabels[value] ?? String(value);
  if (typeof value === 'number') {
    if (['at', 'expiresAt', 'probeExpiresAt', 'probeDeadline', 'validUntil', 'settledAt', 'nbf', 'exp',
      'createdAt', 'issuedAt', 'decisionAt', 'effectiveDeadline', 'contextAccessDeadline'].includes(key)) {
      return timestamp(value);
    }
    if (key?.endsWith('Minor')) return (value / 100).toFixed(2) + ' 元 / ' + value + ' 分';
  }
  if (key?.endsWith('Id') || key?.endsWith('Did') || key?.endsWith('Hash')) {
    return element('code', {}, String(value));
  }
  return String(value);
}

function evidenceContent(type, data) {
  if (!data || (Array.isArray(data) && !data.length) || (typeof data === 'object' && !Object.keys(data).length)) {
    return element('p', { class: 'muted' }, '暂无可查看的证据.');
  }
  if (type === 'delegations' && Array.isArray(data)) {
    return element('ol', { class: 'timeline' }, ...data.map((item) =>
      element('li', {},
        element('div', { class: 'toolbar' },
          element('strong', {}, item.level ?? (!item.parentId ? 'G0' : item.parentId === item.rootId ? 'G1' : 'G2')),
          status(item.status)),
        genericValue(item))));
  }
  if (type === 'decisions' && Array.isArray(data)) {
    return element('ol', { class: 'timeline' }, ...data.map((item) =>
      element('li', {},
        element('div', { class: 'toolbar' },
          item.action ? element('strong', {}, item.action) : null,
          status(item.outcome ?? item.status),
          item.requestId && !item.decisionId ? element('small', {}, '预检记录') : null),
        genericValue({ ...item, contextVersion: item.contextVersion || null }),
        allowed('auditDecisions') && item.decisionId ? link('读取完整决定', 'decisions', item.decisionId) : null)));
  }
  return genericValue(data);
}

function evidenceSection() {
  const body = element('div', { 'aria-live': 'polite' });
  let selected = 'purchase';
  let projection = null;
  let unavailable = false;
  const tabs = new Map();
  const update = () => {
    for (const [key, tab] of tabs) tab.setAttribute('aria-pressed', String(key === selected));
    if (!projection) {
      body.replaceChildren(element('p', { class: 'muted' }, unavailable ? '证据查询暂不可用.' : '正在查询证据.'));
      return;
    }
    body.replaceChildren(evidenceContent(selected, projection[selected]));
  };
  for (const [key, name] of sections) {
    tabs.set(key, button(name, () => {
      selected = key;
      update();
    }, true));
  }
  update();
  const node = card('业务证据', element('div', { class: 'tab-list', role: 'group', 'aria-label': '证据视图' }, ...tabs.values()), body);
  node.tabIndex = -1;
  return {
    node,
    update(data) {
      projection = data;
      unavailable = !data;
      update();
    },
  };
}

function runSteps(steps) {
  if (!steps?.length) return element('p', { class: 'muted' }, '等待业务步骤.');
  return element('ol', { class: 'timeline' }, ...steps.map((step) =>
    element('li', {},
      element('div', { class: 'toolbar' }, element('strong', {}, stageLabels[step.stage] ?? step.stage), status(step.status)),
      facts([
        ['时间', timestamp(step.at)],
        ['操作 ID', step.operationId ? element('code', {}, step.operationId) : null],
        ['原交易 txId', step.txId ? element('code', {}, step.txId) : null],
        ['委托 ID', step.grantId ? element('code', {}, step.grantId) : null],
        ['入块校验码', step.validationCode],
        ['结果码', step.code],
      ]))));
}

function runList(runs) {
  if (!runs?.length) return card('我的采购运行',
    element('p', { class: 'muted' }, '暂无已确认的采购运行.'),
    link('发起采购对话', 'chat', null, { class: 'button' }));
  return card('我的采购运行', element('ul', { class: 'records' }, ...runs.map((run) =>
    element('li', {},
      element('div', { class: 'toolbar' },
        link(run.task?.productId || run.runId, 'runs', run.runId),
        status(run.status),
        run.task?.mode ? element('span', { class: 'muted' }, modeLabels[run.task.mode] ?? run.task.mode) : null),
      facts([['运行 ID', element('code', {}, run.runId)], ['任务 ID', run.taskId ? element('code', {}, run.taskId) : null]])))));
}

function runActions(run, refresh, epoch) {
  const actions = run.allowedActions ?? [];
  return element('div', { class: 'toolbar actions' }, ...[['suspend', '暂停 G1'], ['resume', '恢复 G1']]
    .filter(([operation]) => actions.includes(operation))
    .map(([operation, name]) => {
      const action = button(name, null, true);
      action.addEventListener('click', busy(action, async () => {
        const idempotencyKey = retryKey(operation, run.runId, run.grantRevision);
        await write('/runs/' + encodeURIComponent(run.runId) + '/' + operation, undefined, { idempotencyKey });
        if (epoch === state.epoch) await refresh();
      }));
      return action;
    }));
}

function toolTraces(traces) {
  if (!traces?.length) return element('p', { class: 'muted' }, '暂无工具调用.');
  const displayFields = [
    'callId', 'operationId', 'txId', 'decision', 'decisionId', 'quoteId', 'orderId',
    'grantId', 'errorCode', 'code', 'actionId', 'actionStatus', 'productId',
    'quantity', 'totalAmountMinor', 'caseId', 'provider', 'requestedModel', 'responseModel',
  ];
  return element('ul', { class: 'records' }, ...traces.map((trace) => {
    const output = trace.output ?? {};
    const unknownOutcome = output.actionStatus === 'OUTCOME_UNKNOWN' || output.outcome === 'UNKNOWN';
    return element('li', {},
      element('div', { class: 'toolbar' },
        element('strong', {}, trace.toolName === 'model_result' ? '模型运行结果' : trace.toolName),
        trace.toolName === 'model_result' ? element('code', {}, trace.toolName) : null,
        status(unknownOutcome ? 'OUTCOME_UNKNOWN' : output.decision || (trace.isError ? 'failed' : 'returned'))),
      facts([
        ['模型步骤', trace.step > 0 ? trace.step : null],
        ['耗时 (ms)', trace.durationMs],
        ...displayFields.map((key) => [
          fieldLabels[key] ?? key,
          genericValue(trace[key] ?? output[key] ?? (key === 'grantId' ? output.grant?.grantId : null), key),
        ]),
      ]));
  }));
}

async function showRuns(id, epoch) {
  if (!id) {
    view.append(heading('采购运行'));
    const response = await request('/runs');
    if (epoch === state.epoch) view.append(runList(response.runs));
    return;
  }
  const detail = element('div', { class: 'stack' });
  const progress = element('div', { class: 'stack' });
  const evidence = evidenceSection();
  view.append(heading('采购运行详情'), element('div', { class: 'stack' },
    element('div', { class: 'toolbar' },
      link('返回采购运行', 'runs', null, { class: 'button secondary' }),
      button('查看业务证据', () => { evidence.node.focus(); }, true)),
    element('div', { class: 'split' }, detail, progress),
    evidence.node));
  const path = '/runs/' + encodeURIComponent(id);
  let lastRun = '';
  let lastEvidence = '';
  const refresh = async () => {
    const [runResult, evidenceResult] = await Promise.allSettled([request(path), request(path + '/evidence')]);
    if (epoch !== state.epoch) return;
    if (runResult.status === 'rejected') throw runResult.reason;
    const run = runResult.value;
    const encodedRun = JSON.stringify(run);
    if (encodedRun !== lastRun) {
      lastRun = encodedRun;
      detail.replaceChildren(card('任务及运行状态',
        status(run.status),
        facts([
          ['运行 ID', element('code', {}, run.runId)], ['任务 ID', element('code', {}, run.taskId)],
          ['当前阶段', stageLabels[run.stage] ?? run.stage],
          ['G1 状态', run.grantStatus ? status(run.grantStatus) : null],
        ]),
        run.task ? draftSummary(run.task) : null,
        runActions(run, refresh, epoch)));
      progress.replaceChildren(card('执行进度', runSteps(run.steps)),
        card('工具轨迹', toolTraces(run.traces)));
    }
    if (evidenceResult.status === 'rejected' && evidenceResult.reason.status === 401) throw evidenceResult.reason;
    const projection = evidenceResult.status === 'fulfilled' ? evidenceResult.value : null;
    const encodedEvidence = JSON.stringify(projection);
    if (encodedEvidence !== lastEvidence) {
      lastEvidence = encodedEvidence;
      evidence.update(projection);
    }
  };
  await refresh();
  if (epoch === state.epoch) poll(epoch, refresh);
}

async function showDecisions(id, epoch) {
  view.append(heading('决策审计', '输入可核对的决定 ID, 读取当前身份获准查看的 C 网关决定.'),
    card('查询决定', lookup('决定 ID', '读取', id, (decisionId) => navigate('decisions', decisionId))));
  if (!id) return;
  const data = await request('/decisions/' + encodeURIComponent(id));
  if (epoch === state.epoch) {
    view.append(element('div', { class: 'stack' }, card('网关决定', genericValue(data))));
  }
}

function poll(epoch, action, active = () => true) {
  if (epoch !== state.epoch || !active()) return;
  state.poll = setTimeout(async () => {
    if (epoch !== state.epoch) return;
    try {
      await action();
    } catch (error) {
      showError(error);
    }
    poll(epoch, action, active);
  }, 2500);
}

async function render() {
  clearTimeout(state.poll);
  const epoch = ++state.epoch;
  const { page, id } = currentRoute();
  view.replaceChildren();
  setNotice();
  if (!state.session) {
    showAccount('login');
    showLogin();
    return;
  }

  let target = page;
  if (!target || target === 'login') {
    target = allowed('procure') ? 'runs' : allowed('managePurchasingAuthority') ? 'management' : 'decisions';
    history.replaceState(null, '', route(target));
  }
  showAccount(target);
  try {
    if (target === 'management' && allowed('managePurchasingAuthority')) await showManagement(id, epoch);
    else if (target === 'chat' && allowed('procure')) await showChat(id, epoch);
    else if (target === 'runs' && allowed('procure')) await showRuns(id, epoch);
    else if (target === 'decisions' && allowed('auditDecisions')) await showDecisions(id, epoch);
    else view.append(heading('此操作未授权', '请从导航选择当前账号可以使用的功能.'));
  } catch (error) {
    if (epoch === state.epoch) showError(error);
  }
}

async function start() {
  let error;
  const results = await Promise.allSettled([request('/health/ready'), request('/session')]);
  const [readiness, session] = results;
  if (readiness.status === 'fulfilled') showDomain(readiness.value.domainId, readiness.value.ready);
  else showDomain(null, false);
  if (session.status === 'fulfilled') state.session = session.value;
  else if (session.reason.status !== 401) error = session.reason;
  window.addEventListener('hashchange', render);
  document.querySelector('.skip-link').addEventListener('click', (event) => {
    event.preventDefault();
    document.querySelector('#main').focus();
  });
  await render();
  if (error) showError(error);
}

start();
