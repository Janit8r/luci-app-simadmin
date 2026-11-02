'use strict';
'require view';
'require ui';

/*
 * SimAdmin 概览页
 * -----------------
 * 主体仍是内嵌的 SimAdmin Web UI（iframe），但在顶部加一条原生 IMS / VoLTE
 * 状态带，数据来自后端 `/api/volte/control`。这样即使 iframe 里的页面加载失败
 * （后端重启、端口未起），也能在 LuCI 里看到 IMS 注册到哪一步、卡在哪里。
 */

var base = 'http://' + window.location.hostname + ':3000/';
var api = base + 'api/volte/';

var frame = null;
var holder = null;
var timer = null;
var statusTimer = null;
var down = false;
var control = null;
var busy = false;

/* ------------------------------------------------------------------ 工具 */

function call(method, path, body) {
	var opt = { method: method, cache: 'no-store' };
	if (body !== undefined) {
		opt.headers = { 'Content-Type': 'application/json' };
		opt.body = JSON.stringify(body);
	}
	return fetch(api + path, opt).then(function(res) {
		return res.json();
	}).then(function(json) {
		if (!json || json.status !== 'ok')
			throw new Error((json && json.message) || 'request failed');
		return json.data;
	});
}

function ts(v) {
	if (!v)
		return '—';
	var d = new Date(v * 1000);
	var pad = function(n) { return (n < 10 ? '0' : '') + n; };
	return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
		pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

var PHASE_STYLE = {
	registered: { color: '#1a7f37', bg: '#e6f4ea', text: '已注册' },
	starting:   { color: '#8a6d00', bg: '#fff8e1', text: '注册中' },
	degraded:   { color: '#b3261e', bg: '#fce8e6', text: '降级' },
	stopping:   { color: '#5f6368', bg: '#f1f3f4', text: '停止中' },
	disabled:   { color: '#5f6368', bg: '#f1f3f4', text: '已关闭' }
};

var STAGE_TEXT = {
	starting: '启动',
	identity: '读取 IMSI/AID',
	identity_aka: 'USIM AKA',
	radio: '等待无线',
	bearer: '建立 IMS 承载',
	pcscf: 'P-CSCF 发现',
	register_ipsec: 'IPsec 注册',
	register_udp: 'UDP 注册',
	registered: '已注册',
	stopping: '停止'
};

function button(label, extra, disabled, onclick) {
	var attrs = {
		'class': 'btn cbi-button' + (extra ? ' ' + extra : ''),
		'style': 'padding:2px 10px;font-size:12px;',
		'click': onclick
	};
	if (disabled)
		attrs.disabled = 'disabled';
	return E('button', attrs, [label]);
}

function chip(label, value, tone) {
	var style = 'display:inline-flex;align-items:center;gap:6px;padding:3px 10px;' +
		'border-radius:12px;font-size:12px;line-height:18px;white-space:nowrap;';
	if (tone)
		style += 'color:' + tone.color + ';background:' + tone.bg + ';';
	else
		style += 'color:#3c4043;background:#f1f3f4;';
	return E('span', { 'style': style }, [
		E('span', { 'style': 'opacity:.65' }, [label]),
		E('span', { 'style': 'font-weight:600' }, [value])
	]);
}

/* -------------------------------------------------------------- 状态渲染 */

function renderStatus(data) {
	control = data;
	var cfg = (data && data.config) || {};
	var rt = (data && data.runtime) || {};
	var phase = rt.phase || 'disabled';
	var tone = PHASE_STYLE[phase] || PHASE_STYLE.disabled;
	var node = document.getElementById('simadmin-volte-bar');
	if (!node)
		return;

	var parts = [
		chip('IMS', rt.registered ? '已注册' : tone.text, rt.registered ? PHASE_STYLE.registered : tone),
		chip('阶段', STAGE_TEXT[rt.stage] || rt.stage || '—'),
		chip('发送/接收', (rt.sent_count || 0) + ' / ' + (rt.received_count || 0))
	];

	if (rt.registration_mode)
		parts.push(chip('通道', rt.registration_mode === 'register_ipsec' ? 'IPsec' : 'UDP'));
	if (rt.interface)
		parts.push(chip('网卡', rt.interface));
	if (cfg.pcscf)
		parts.push(chip('P-CSCF', cfg.pcscf));
	else if (rt.pcscf)
		parts.push(chip('P-CSCF', rt.pcscf + '（自动）'));
	else
		parts.push(chip('P-CSCF', '未配置', PHASE_STYLE.starting));
	if (rt.ue_address)
		parts.push(chip('UE', rt.ue_address));
	if (rt.smsc)
		parts.push(chip('SMSC', rt.smsc));
	if (rt.own_number)
		parts.push(chip('本机号', rt.own_number));
	if (rt.aka_transport)
		parts.push(chip('AKA', rt.aka_transport === 'qmi_proxy' ? 'qmi-proxy' : 'raw QMUX'));
	if (rt.bearer_source)
		parts.push(chip('承载', rt.bearer_source === 'qmicli' ? 'qmicli' : 'raw QMUX'));
	if (rt.registered_at)
		parts.push(chip('注册于', ts(rt.registered_at)));
	if (rt.next_retry_at && phase !== 'registered')
		parts.push(chip('下次重试', ts(rt.next_retry_at)));

	if (rt.last_error)
		parts.push(E('span', {
			'style': 'color:#b3261e;font-size:12px;max-width:46vw;overflow:hidden;' +
				'text-overflow:ellipsis;white-space:nowrap;',
			'title': rt.last_error
		}, [rt.last_error]));

	var toggleLabel = cfg.feature_enabled ? '关闭 IMS' : '启用 IMS';
	var smsLabel = cfg.sms_enabled ? '关闭 IMS 短信' : '启用 IMS 短信';

	var actions = [
		button(toggleLabel, 'cbi-button-action', busy, function() {
			act('feature', { enabled: !cfg.feature_enabled });
		}),
		button(smsLabel, '', busy || !cfg.feature_enabled, function() {
			act('sms', { enabled: !cfg.sms_enabled });
		}),
		button('P-CSCF', '', busy, function() {
			editPcscf(cfg);
		}),
		button('重新注册', '', busy || !cfg.feature_enabled, function() {
			act('refresh', {});
		})
	];

	while (node.firstChild)
		node.removeChild(node.firstChild);
	parts.forEach(function(p) { node.appendChild(p); });
	actions.forEach(function(a) { node.appendChild(a); });
}

function act(path, body) {
	if (busy)
		return;
	busy = true;
	call('POST', path, body).then(function(data) {
		renderStatus(data);
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, ['IMS 操作失败: ' + err.message]), 'error');
	}).finally(function() {
		busy = false;
	});
}

/*
 * 手工填写 P-CSCF。
 *
 * 本网实测自动发现全军覆没，所以这个入口是必须的：
 *   - QMI `--wds-get-current-settings` 没有 0x1F（P-CSCF）TLV
 *   - `AT+CGCONTRDP` 只对 AT 激活的上下文吐 P-CSCF，而 QMI 拉起的会话
 *     根本不出现在这个命令里
 *   - 公网 DNS 不发布 pcscf.*.3gppnetwork.org，而且那台 DNS 对任意不存在
 *     的域名也回 NOERROR/0（实测），所以 DNS 发现的结果不可信
 *
 * 留空 = 回到自动发现。
 */
function editPcscf(cfg) {
	var input = E('input', {
		'class': 'cbi-input-text',
		'style': 'width:100%;box-sizing:border-box',
		'placeholder': '例如 2408:8142:6001:1007::1（留空 = 自动发现）',
		'value': cfg.pcscf || ''
	});

	return ui.showModal('P-CSCF', [
		E('p', { 'style': 'margin:0 0 10px;line-height:1.6' }, [
			'IMS 注册必须先知道 P-CSCF。本网实测无法自动发现，' +
			'需要时在这里手工指定（IPv4 / IPv6 字面量，不要带引号）。'
		]),
		input
	], [
		button('保存', 'cbi-button-action important', false, function() {
			var v = (input.value || '').trim();
			ui.hideModal();
			act('settings', { pcscf: v });
		}),
		button('取消', '', false, function() {
			ui.hideModal();
		})
	]);
}

function pollStatus() {
	call('GET', 'control').then(renderStatus).catch(function() {
		var node = document.getElementById('simadmin-volte-bar');
		if (!node)
			return;
		while (node.firstChild)
			node.removeChild(node.firstChild);
		node.appendChild(chip('IMS', '后端未就绪', PHASE_STYLE.degraded));
	});
}

function watchStatus() {
	pollStatus();
	if (!statusTimer)
		statusTimer = setInterval(pollStatus, 5000);
}

/* ------------------------------------------------------------- iframe 存活 */

function probe() {
	if (!frame || !frame.isConnected)
		return;
	fetch(base, { mode: 'no-cors', cache: 'no-store' }).then(function() {
		if (down) {
			down = false;
			frame.src = base;
		}
	}).catch(function() {
		down = true;
	});
}

function watch() {
	if (!timer)
		timer = setInterval(probe, 5000);
}

return view.extend({
	load: function() {
		return Promise.resolve();
	},

	render: function() {
		if (!frame) {
			frame = E('iframe', {
				'src': base,
				'title': 'SimAdmin',
				'style': 'width:100%;height:100%;border:0;display:block;background:#fff',
				'allow': 'clipboard-read; clipboard-write; fullscreen'
			});
			holder = E('div', {
				'style': 'height:70vh;min-height:320px;background:#fff;overflow:hidden'
			}, [frame]);
		}

		var bar = E('div', {
			'id': 'simadmin-volte-bar',
			'style': 'display:flex;flex-wrap:wrap;align-items:center;gap:6px;' +
				'padding:8px 10px;margin-bottom:8px;border:1px solid #e0e0e0;' +
				'border-radius:6px;background:#fafafa;'
		}, [chip('IMS', '读取中…')]);

		var box = E('div', {}, [bar, holder]);

		var fit = function() {
			if (!holder.isConnected)
				return;
			var top = holder.getBoundingClientRect().top;
			var h = Math.max(320, window.innerHeight - top - 12);
			if (Math.abs(holder.offsetHeight - h) > 2)
				holder.style.height = h + 'px';
		};

		requestAnimationFrame(fit);
		window.addEventListener('resize', fit);
		watch();
		watchStatus();

		return box;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
