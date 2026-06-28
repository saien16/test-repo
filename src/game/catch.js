/* ============================================================
   むしとりバトル — catch.js（ほかく＝むしとの かけひき）
   フィールドで「けはい」に たどりついたら enterCatch(sign) が よばれる。
   ちかよる／そっと／まつ／あみ の 4つの 行動で むしを つかまえる。
   おわったら returnToField({caught,key,name,pts,mm,big}) で フィールドへ もどる。
   ※ import/export しない。G/CONFIG/U/BUGS/bugSprite/Sound/showScreen/returnToField は
     ほかの ファイルで さだめずみ（グローバル共有）。
   ============================================================ */

/* むしの ビジュアル さいだいサイズ(px)。アリーナに おさまるよう ひかえめ */
var CS_BUG_PX_MIN = 64;
var CS_BUG_PX_MAX = 118;

/* ほかくシーンに はいる。sign = {tx,ty,key,...} */
function enterCatch(sign) {
  var key = sign.key;
  var bug = BUGS[key];
  if (!bug) { returnToField(null); return; } // ねんのため

  // 個体差(0.85〜1.35) と 夜ボーナス で サイズと でかむし判定
  // ⑦(任意・軽) でかい!! を レア度と そうかん: レア(w 小)ほど 大物が でやすい
  var w = bug.w || 3;
  var rareBoost = w === 1 ? 0.10 : w === 2 ? 0.05 : 0; // やり過ぎない
  var sizeF = 0.85 + U.rnd() * 0.5 + rareBoost;
  sizeF = U.clamp(sizeF, 0.85, 1.45);
  var big = sizeF >= 1.25;
  var mm = Math.round(bug.sizeBase * sizeF * (G.night ? 1.06 : 1));

  // ほかく中の じょうたい
  G.cs = {
    key: key,
    name: bug.name,
    dist: CONFIG.START_DIST, // きょり(m)
    alert: bug.alertBase || 0, // けいかい度 0〜100
    sizeF: sizeF,
    big: big,
    mm: mm,
    pts: bug.pts * (big ? 2 : 1),
    over: false, // けっちゃくが ついたか
    busy: false, // えんしゅつ中（ボタン れんだ ふせぎ）
    busyAnim: false, // 吸い込み／逃走の アニメ中（right を いじらない）
    warned: false, // 「にげそう!」予告ずみか
    graced: false, // 予告の 1かい ゆうよを つかったか
    // あみ（網）: えらんでいる網id。変種が もちもの>0 なら それ、なければ basic
    net: (G.curNet !== 'basic' && (G.nets[G.curNet] || 0) > 0) ? G.curNet : 'basic',
    basicBroken: false, // basicが こわれた→このエンカウントだけ てづかみ
  };

  G.player.busy = true;
  buildCatchUI();
  csLog('🌿 ガサッ…! <b>' + bug.name + '</b>を みつけた！（' + CONFIG.START_DIST + 'm さき・およそ ' + mm + 'mm）');
  Sound.sfx.select();
  showScreen('catch-screen');

  // combo>=2 なら もりあげる（G.combo は core が かんり・ここでは よむだけ）
  var combo = (typeof G !== 'undefined' && G && typeof G.combo === 'number') ? G.combo : 0;
  if (combo >= 2) {
    csLog('🔥 コンボ ×' + combo + ' つづいてる！ この いきおいで いこう！');
  }

  // でかむしは とうじょうで ひとこえ
  if (big) {
    Sound.sfx.warn();
    csLog('✨ うわっ、<b>でかい!!</b> ' + mm + 'mm の おおもの だ！');
  }
  csRender();
}

/* #catch-root に UIを くみたてる */
function buildCatchUI() {
  var root = document.getElementById('catch-root');
  if (!root) return;
  var cs = G.cs;
  var bugPx = csBugPx();
  root.innerHTML =
    '<div class="cs-top">' +
      '<span class="cs-dist" id="cs-dist">あと ' + cs.dist + 'm</span>' +
      '<span class="cs-name" id="cs-name">' + cs.name + (cs.big ? ' ★' : '') + '</span>' +
    '</div>' +
    '<div class="cs-alert-wrap">' +
      '<div class="cs-alert-label">' +
        '<span>けいかい <span class="cs-alert-state" id="cs-alert-state">よゆう😺</span></span>' +
        '<span id="cs-alert-num">0%</span>' +
      '</div>' +
      '<div class="cs-alert-bar"><div class="cs-alert-fill" id="cs-alert-fill"></div></div>' +
    '</div>' +
    '<div class="cs-arena" id="cs-arena">' +
      '<div class="cs-bug" id="cs-bug">' + bugSprite(cs.key, bugPx) + '</div>' +
      '<div class="cs-hunter" id="cs-hunter">🥅</div>' +
    '</div>' +
    '<div class="cs-log" id="cs-log"></div>' +
    '<div class="cs-nets" id="cs-nets"></div>' +
    '<div class="cs-actions">' +
      '<button class="cs-btn approach" id="cs-approach">ちかよる<small>2m すすむ・ばれやすい</small></button>' +
      '<button class="cs-btn sneak" id="cs-sneak">そっと<small>1m すすむ・しずか</small></button>' +
      '<button class="cs-btn wait" id="cs-wait">まつ<small>けいかいを さげる</small></button>' +
      '<button class="cs-btn net" id="cs-net"><span class="cs-net-main">あみを ふる！</span><small id="cs-net-acc"></small></button>' +
    '</div>';

  document.getElementById('cs-approach').onclick = function () { csAct('approach'); };
  document.getElementById('cs-sneak').onclick = function () { csAct('sneak'); };
  document.getElementById('cs-wait').onclick = function () { csAct('wait'); };
  document.getElementById('cs-net').onclick = function () { csSwing(); };

  csBuildNetSelector();
}

/* ---- あみセレクタ（横ならびチップ）を くみたてる ----
   basicは つねに／変種は G.nets[id]>0 のものだけ。
   各チップ: 絵文字＋なまえ＋いまの きょりの ◎○△＋こわれ目安（＋変種は ×のこり）。
   てづかみ中（basicBroken）は てづかみチップを みせる。 */
function csBuildNetSelector() {
  var box = document.getElementById('cs-nets');
  if (!box) return;
  var cs = G.cs;
  if (!cs) { box.innerHTML = ''; return; }
  var html = '';

  if (cs.basicBroken) {
    // てづかみ中: 専用チップ（えらべない・アクティブ表示のみ）
    html += '<div class="cs-net-chip active hand" id="cs-netchip-hand">' +
      '<span class="cs-nc-ico">🤚</span>' +
      '<span class="cs-nc-body">' +
        '<span class="cs-nc-name">てづかみ</span>' +
        '<span class="cs-nc-sub">あみが こわれた…</span>' +
      '</span>' +
    '</div>';
    box.innerHTML = html;
    return;
  }

  var ids = csNetList();
  for (var i = 0; i < ids.length; i++) {
    html += csNetChipHTML(ids[i]);
  }
  box.innerHTML = html;

  // タップで きりかえ
  for (var j = 0; j < ids.length; j++) {
    (function (id) {
      var el = document.getElementById('cs-netchip-' + id);
      if (el) el.onclick = function () { csPickNet(id); };
    })(ids[j]);
  }
}

/* えらべる網idの いちらん（basic＋もちもの>0の変種・NETSの じゅんばん） */
function csNetList() {
  var out = ['basic'];
  try {
    var keys = Object.keys(NETS);
    for (var i = 0; i < keys.length; i++) {
      var id = keys[i];
      if (id === 'basic') continue;
      if ((G.nets[id] || 0) > 0) out.push(id);
    }
  } catch (e) { /* NETS なくても basic だけ */ }
  return out;
}

/* チップ1まいの HTML */
function csNetChipHTML(id) {
  var cs = G.cs;
  var n = (typeof NETS !== 'undefined' && NETS[id]) ? NETS[id] : null;
  var name = n ? n.name : 'あみ';
  var rate = netHit(id, cs.dist);
  var hm = netHitMark(rate);
  var risk = netRiskLabel(id);
  var active = (id === cs.net);
  var isBasic = (id === 'basic');
  var cntTxt = isBasic ? '∞' : ('×' + (G.nets[id] || 0));
  return '<button class="cs-net-chip risk' + risk.lv + (active ? ' active' : '') + '" id="cs-netchip-' + id + '">' +
      '<span class="cs-nc-ico">' + (id === 'gold' ? '👑' : '🥅') + '</span>' +
      '<span class="cs-nc-body">' +
        '<span class="cs-nc-name">' + name + ' <span class="cs-nc-cnt">' + cntTxt + '</span></span>' +
        '<span class="cs-nc-sub">' +
          '<span class="cs-mark ' + hm.cls + '">' + hm.mark + '</span> ' +
          '<span class="cs-nc-risk lv' + risk.lv + '">' + risk.word + '</span>' +
        '</span>' +
      '</span>' +
    '</button>';
}

/* 網を えらぶ（cs.net＋G.curNet 更新→再描画） */
function csPickNet(id) {
  var cs = G.cs;
  if (!cs || cs.over || cs.busy || cs.basicBroken) return;
  if (id !== 'basic' && (G.nets[id] || 0) <= 0) return; // ねんのため
  if (cs.net === id) return;
  cs.net = id;
  G.curNet = id; // 捕獲シーンを またいで きおく（core共有）
  Sound.sfx.select();
  csBuildNetSelector();
  csRender();
}

/* むしの 見た目サイズ(px)。個体差で すこし おおきく */
function csBugPx() {
  var f = U.clamp(G.cs.sizeF, 0.85, 1.45);
  return Math.round(CS_BUG_PX_MIN + (CS_BUG_PX_MAX - CS_BUG_PX_MIN) * ((f - 0.85) / 0.5));
}

/* ログ欄に じっきょうを だす */
function csLog(html) {
  var el = document.getElementById('cs-log');
  if (el) el.innerHTML = html;
}

/* きょり(m) → えらんでいる網の 実効 命中りつ(0〜1)
   ・基本: netHit(cs.net, cs.dist)
   ・basicBroken（てづかみ）: 0mなら0.30・それ以外0.05 */
function csHitRate() {
  var cs = G.cs;
  if (!cs) return 0.3;
  if (cs.basicBroken) {
    return (Math.round(cs.dist) <= 0) ? 0.30 : 0.05;
  }
  try {
    return netHit(cs.net, cs.dist);
  } catch (e) {
    return 0.3;
  }
}

/* 命中りつ → めやす記号 ◎/○/△ と クラス名 */
function csHitMark(rate) {
  if (rate >= 0.75) return { mark: '◎', cls: 'good', word: 'ねらいめ！' };
  if (rate >= 0.55) return { mark: '○', cls: 'ok', word: 'いけそう' };
  return { mark: '△', cls: 'bad', word: 'むずかしい' };
}

/* 画面（きょり・ゲージ・ボタン・むし位置）を かきなおす */
function csRender() {
  var cs = G.cs;
  if (!cs) return;
  var a = Math.round(cs.alert);
  var aClamp = Math.min(100, Math.max(0, a));
  var rate = csHitRate();
  var hm = csHitMark(rate);
  var round0 = Math.round(cs.dist) <= 0; // 0m（ちかすぎ）

  // きょりバッジ: めやす記号を 色つきで そえる（数値%も いきる）
  var dist = document.getElementById('cs-dist');
  if (dist) {
    var distTxt = cs.dist <= 1 ? '🎯 とどく！' : 'あと ' + cs.dist + 'm';
    if (round0) distTxt = '⚠️ ちかすぎ！';
    dist.innerHTML = distTxt + ' <span class="cs-mark ' + hm.cls + '">' + hm.mark + '</span>';
    dist.classList.remove('mk-good', 'mk-ok', 'mk-bad');
    dist.classList.add('mk-' + hm.cls);
  }

  var fill = document.getElementById('cs-alert-fill');
  if (fill) {
    fill.style.width = aClamp + '%';
    fill.classList.toggle('warn', aClamp >= 70 && aClamp < 90);
    fill.classList.toggle('danger', aClamp >= 90); // ≥90 で 鼓動パルス(CSS)
  }
  var num = document.getElementById('cs-alert-num');
  if (num) num.textContent = aClamp + '%';

  // ⑥ ゲージ脇の じょうたい（色だけに たよらない）
  var stEl = document.getElementById('cs-alert-state');
  if (stEl) {
    var st = csAlertState(aClamp);
    stEl.textContent = st.word + st.emoji;
    stEl.classList.remove('s-calm', 's-care', 's-danger', 's-flee');
    stEl.classList.add(st.cls);
  }

  var arena = document.getElementById('cs-arena');
  if (arena) {
    arena.classList.toggle('warn-glow', aClamp >= 70);
    arena.classList.toggle('danger-glow', aClamp >= 90); // ④ 明滅
  }

  // むしの 横位置: きょりが ちかいほど 左(プレイヤー)へ よる
  var bugEl = document.getElementById('cs-bug');
  if (bugEl) {
    var t = U.clamp(cs.dist / CONFIG.START_DIST, 0, 1); // 0=ちかい 1=とおい
    // えんしゅつ中(吸い込み・逃走)は right を いじらない
    if (!cs.over && !cs.busyAnim) bugEl.style.right = (6 + t * 30) + '%';
    // ② 警戒≥70 で 震える / 解除で 外す
    bugEl.classList.toggle('tremble', aClamp >= 70 && !cs.over);
  }

  // 網ボタンの メイン名（えらんでいる網名／てづかみ）
  var mainEl = document.querySelector('#cs-net .cs-net-main');
  if (mainEl) {
    if (cs.basicBroken) {
      mainEl.textContent = 'てづかみ！';
    } else {
      var nn = (typeof NETS !== 'undefined' && NETS[cs.net]) ? NETS[cs.net] : null;
      mainEl.textContent = (nn ? nn.name : 'あみ') + ' を ふる！';
    }
  }

  // あみ命中りつ ひょうじ（記号＋%＋こわれ目安）。てづかみ・0mは ちゅういを出す
  var accEl = document.getElementById('cs-net-acc');
  if (accEl) {
    var riskTxt = '';
    if (!cs.basicBroken) {
      var risk = netRiskLabel(cs.net);
      riskTxt = ' ・<span class="cs-nc-risk lv' + risk.lv + '">' + risk.word + '</span>';
    }
    if (cs.basicBroken) {
      accEl.innerHTML = '<span class="cs-mark ' + hm.cls + '">' + hm.mark + '</span> てづかみ やく ' + Math.round(rate * 100) + '%'
        + (round0 ? '（ちかいと とれる！）' : '（ちかづこう）');
    } else if (round0) {
      accEl.innerHTML = '<span class="cs-mark ' + hm.cls + '">' + hm.mark + '</span> ちかすぎ！ やく ' + Math.round(rate * 100) + '%' + riskTxt;
    } else {
      accEl.innerHTML = '<span class="cs-mark ' + hm.cls + '">' + hm.mark + '</span> めいちゅう やく ' + Math.round(rate * 100) + '%' + riskTxt;
    }
  }
  var netBtn = document.getElementById('cs-net');
  if (netBtn) {
    netBtn.classList.remove('acc-good', 'acc-ok', 'acc-bad');
    netBtn.classList.add('acc-' + hm.cls);
    // ⑤ 予告(warn)中は 網ボタンを 強調パルス
    netBtn.classList.toggle('urge', cs.warned && !cs.over);
  }

  // ⑤ 予告中の さそい「いま あみ！」
  csUpdateWarnPop(cs.warned && !cs.over && aClamp >= CONFIG.ALERT_WARN);

  // 網チップの ◎○△ は きょりで かわる→ さい構築
  csBuildNetSelector();

  // ボタン ゆうこう／むこう
  csSetButtons(!cs.busy && !cs.over);
}

/* ⑥ けいかい度 → じょうたい（絵文字＋ことば＋クラス） */
function csAlertState(a) {
  if (a < 40) return { word: 'よゆう', emoji: '😺', cls: 's-calm' };
  if (a < 70) return { word: 'ちゅうい', emoji: '😼', cls: 's-care' };
  if (a < 90) return { word: 'あぶない', emoji: '🙀', cls: 's-danger' };
  return { word: 'にげる！', emoji: '😾', cls: 's-flee' };
}

/* ⑤ 「いま あみ！」さそいポップの 出し入れ（常設・点滅はCSS） */
function csUpdateWarnPop(show) {
  var arena = document.getElementById('cs-arena');
  if (!arena) return;
  var pop = arena.querySelector('.cs-warn-now');
  if (show) {
    if (!pop) {
      pop = document.createElement('div');
      pop.className = 'cs-warn-now';
      pop.textContent = 'いま あみ！';
      arena.appendChild(pop);
    }
  } else if (pop) {
    pop.remove();
  }
}

/* ぜんボタンの ゆうこう／むこうを いっかつ きりかえ */
function csSetButtons(enabled) {
  var cs = G.cs;
  var ids = ['cs-approach', 'cs-sneak', 'cs-wait', 'cs-net'];
  ids.forEach(function (id) {
    var b = document.getElementById(id);
    if (!b) return;
    b.disabled = !enabled;
  });
  if (enabled) {
    // きょり0mでは これ以上 すすめない
    var ap = document.getElementById('cs-approach');
    var sn = document.getElementById('cs-sneak');
    if (cs.dist <= 0) { if (ap) ap.disabled = true; if (sn) sn.disabled = true; }
  }
  // 網チップも えんしゅつ中は さわれない見た目に
  var nets = document.getElementById('cs-nets');
  if (nets) nets.classList.toggle('locked', !enabled);
}

/* 行動: approach / sneak / wait */
function csAct(mode) {
  var cs = G.cs;
  if (!cs || cs.over || cs.busy) return;
  cs.busy = true;
  csSetButtons(false);
  Sound.sfx.select();

  if (mode === 'wait') {
    // まつ: 30%-0.5 / 30%-1 / 20%±0 / 20%+1.5（×10して けいかい度に）
    var r = U.rnd();
    var dA = r < 0.3 ? -5 : r < 0.6 ? -10 : r < 0.8 ? 0 : 15;
    cs.alert = U.clamp(cs.alert + dA, 0, 200);
    csLog(dA < 0 ? '🤫 いきを ひそめて まった…（けいかい ' + dA + '）'
        : dA === 0 ? '🤫 いきを ひそめて まった…（へんか なし）'
        : '😨 もぞもぞ して かえって あやしまれた！（けいかい +' + dA + '）');
  } else {
    var stepM = mode === 'approach' ? 2 : 1;
    var dBefore = cs.dist;
    cs.dist = Math.max(0, cs.dist - stepM);
    // けいかい上昇: ちかよる大 / そっと小
    var gain = mode === 'approach' ? (16 + U.rnd() * 14) : (6 + U.rnd() * 8);
    // 距離係数: とおい8m×0.6 → ちかい0m×1.0（ちかいほど ばれやすい）
    var distF = 0.6 + 0.4 * (CONFIG.START_DIST - dBefore) / CONFIG.START_DIST;
    gain *= distF;
    if (G.night) gain *= 0.9; // よるの むしは ねぼけぎみ
    cs.alert = U.clamp(cs.alert + gain, 0, 200);
    csLog((mode === 'approach' ? '🚶 ' : '🐢 そっと ')
      + cs.dist + 'm まで ちかづいた！');
  }

  csRender();
  // すこし えんしゅつ → けっか判定
  setTimeout(function () { csResolveMove(mode); }, mode === 'approach' ? 520 : 600);
}

/* 行動の あとの にげる／予告 判定（まつ・接近 きょうつう） */
function csResolveMove(mode) {
  var cs = G.cs;
  if (!cs || cs.over) return;

  // けいかい100いじょう → そくにげ
  if (cs.alert >= CONFIG.ALERT_FLEE) {
    csFlee('💨 きづかれた！ ' + cs.name + 'は にげてしまった…');
    return;
  }

  // けいかい70いじょう → 予告（1かいの ゆうよ） → 以後 まつ いがいで 逃走チェック
  if (cs.alert >= CONFIG.ALERT_WARN) {
    if (!cs.warned) {
      cs.warned = true;
      cs.graced = true; // この1てで にげない（ゆうよ）
      Sound.sfx.warn();
      var pop = document.getElementById('cs-arena');
      if (pop) csShowWarnPop();
      csLog('⚠️ ' + cs.name + 'が こちらを みている… <b>にげそう だ！</b>');
      cs.busy = false;
      csRender();
      return;
    }
    if (mode !== 'wait') {
      if (U.chance(CONFIG.WARN_FLEE_P)) {
        csFlee('💨 ' + cs.name + 'は きけんを かんじて にげてしまった！');
        return;
      }
    }
  }

  // けいかいが さがれば 予告かいじょ
  if (cs.warned && cs.alert < CONFIG.ALERT_WARN - 15) {
    cs.warned = false;
    csLog('😮‍💨 ' + cs.name + 'は すこし おちついたようだ…');
  }

  cs.busy = false;
  csRender();
}

/* 「にげそう!」ポップを アリーナに 1かい だす */
function csShowWarnPop() {
  var arena = document.getElementById('cs-arena');
  if (!arena) return;
  var old = arena.querySelector('.cs-warn-pop');
  if (old) old.remove();
  var pop = document.createElement('div');
  pop.className = 'cs-warn-pop';
  pop.textContent = 'にげそう！';
  arena.appendChild(pop);
  setTimeout(function () { if (pop.parentNode) pop.remove(); }, 900);
}

/* クラスを つけて 一定時間後に はずす（アニメ完了まち・例外で落ちない） */
function csClassFor(el, cls, ms) {
  if (!el) return;
  el.classList.add(cls);
  setTimeout(function () { if (el && el.classList) el.classList.remove(cls); }, ms || 600);
}

/* ① 白フラッシュを アリーナに 一瞬 だす */
function csFlash() {
  var arena = document.getElementById('cs-arena');
  if (!arena) return;
  var fx = document.createElement('div');
  fx.className = 'cs-flash';
  arena.appendChild(fx);
  setTimeout(function () { if (fx.parentNode) fx.remove(); }, 360);
}

/* ① big のキラキラ */
function csSparkle() {
  var arena = document.getElementById('cs-arena');
  if (!arena) return;
  var box = document.createElement('div');
  box.className = 'cs-sparkle';
  box.innerHTML = '<span>✨</span><span>⭐</span><span>✨</span><span>🌟</span><span>✨</span>';
  arena.appendChild(box);
  setTimeout(function () { if (box.parentNode) box.remove(); }, 900);
}

/* 逃走の 土ぼこり */
function csDust() {
  var arena = document.getElementById('cs-arena');
  if (!arena) return;
  var d = document.createElement('div');
  d.className = 'cs-dust';
  d.textContent = '💨';
  arena.appendChild(d);
  setTimeout(function () { if (d.parentNode) d.remove(); }, 700);
}

/* あみを ふる */
function csSwing() {
  var cs = G.cs;
  if (!cs || cs.over || cs.busy) return;
  cs.busy = true;
  csSetButtons(false);
  Sound.sfx.select();

  var rate = csHitRate();
  var swungNet = cs.net;            // この スイングで つかった網id
  var handMode = cs.basicBroken;    // てづかみ中は こわれ判定なし
  csLog(handMode ? '🤚 えいっ！ てを のばした！' : '🥅 えいっ！ あみを ふった！');

  // ① 網スイングアニメ（虫へ ふる）
  csClassFor(document.getElementById('cs-hunter'), 'swing', 460);

  setTimeout(function () {
    if (!cs || cs.over) return;
    var caught = U.chance(rate);

    // ---- 破損判定: 毎スイング（成功・失敗とも）。てづかみは こわれない ----
    var broke = false;
    if (!handMode) {
      var bp = (typeof NETS !== 'undefined' && NETS[swungNet] && typeof NETS[swungNet].breakP === 'number')
        ? NETS[swungNet].breakP : 0;
      broke = U.chance(bp);
    }

    if (caught) {
      // めいちゅう → ほかく せいこう（壊れても とれていれば OK）
      cs.over = true;
      cs.busyAnim = true;
      Sound.sfx.catch();
      // ① 白フラッシュ＋虫が 網へ 吸い込まれ消える
      csFlash();
      var bugEl = document.getElementById('cs-bug');
      if (bugEl) { bugEl.classList.add('caught-suck'); }
      if (cs.big) { Sound.sfx.big(); csSparkle(); } // big は キラキラ追加・音
      csLog('🎉 やったー！ <b>' + cs.name + '</b>（' + cs.mm + 'mm）を つかまえた！ +' + cs.pts + 'てん'
        + (cs.big ? '（でかボーナス ×2！）' : ''));
      // とれた後の こわれは もちもの整理だけ（演出は ひかえめ）
      if (broke) csApplyBreak(swungNet, true);
      csFinish(true);
    } else {
      // はずれ → 虫が 素早く回避＋小ゆれ → けいかい大up
      Sound.sfx.miss();
      cs.alert = U.clamp(cs.alert + 35, 0, 200);
      var bugEl2 = document.getElementById('cs-bug');
      csClassFor(bugEl2, 'dodge', 360); // ① 素早い回避＋小ゆれ

      if (broke) {
        csApplyBreak(swungNet, false);
      } else {
        csLog('😖 はずした！ ' + cs.name + 'が けいかい している…');
      }
      csRender();
      if (cs.alert >= CONFIG.ALERT_FLEE) {
        if (!broke) csLog('😖 はずした…！ ' + cs.name + 'が おどろいた！');
        setTimeout(function () { csFlee('💨 ' + cs.name + 'は にげてしまった！'); }, 600);
        return;
      }
      if (cs.alert >= CONFIG.ALERT_WARN && !cs.warned) {
        cs.warned = true; cs.graced = true;
        Sound.sfx.warn();
        csShowWarnPop();
      }
      cs.busy = false;
      csRender();
    }
  }, 460);
}

/* 網が こわれた ときの しょり（basic→てづかみ・変種→もちもの-1＋basicへ）
   caught: つかまえた スイングでの 破損か（演出を ひかえめに） */
function csApplyBreak(id, caught) {
  var cs = G.cs;
  if (!cs) return;
  Sound.sfx.miss(); // 破損音（既存ながれ）
  csBreakFx();      // 網が われる 小演出
  var n = (typeof NETS !== 'undefined' && NETS[id]) ? NETS[id] : null;
  var nm = n ? n.name : 'あみ';

  if (id === 'basic') {
    // basic → このエンカウントだけ てづかみ
    cs.basicBroken = true;
    if (!caught) csLog('💥 あみが こわれた！ <b>てづかみ</b>で がんばれ！');
  } else {
    // 変種 → もちものを へらす（0で delete）
    if (G.nets[id] > 0) {
      G.nets[id]--;
      if (G.nets[id] <= 0) delete G.nets[id];
    }
    if (!caught) csLog('💥 ' + nm + 'が こわれた！');
    // アクティブを basic へ もどす（basic自体は こわれていれば てづかみ表示になる）
    if (cs.net === id) {
      cs.net = 'basic';
      G.curNet = 'basic';
    }
  }
  csBuildNetSelector();
}

/* 網が われる 小演出（アリーナに ひびと かけら） */
function csBreakFx() {
  var arena = document.getElementById('cs-arena');
  if (!arena) return;
  var fx = document.createElement('div');
  fx.className = 'cs-break';
  fx.innerHTML = '<span>💥</span>';
  arena.appendChild(fx);
  setTimeout(function () { if (fx.parentNode) fx.remove(); }, 800);
}

/* にげられた */
function csFlee(msg) {
  var cs = G.cs;
  if (!cs || cs.over) { /* over=trueでも 演出ずみなら そのまま */ }
  if (cs) { cs.over = true; cs.busyAnim = true; }
  Sound.sfx.flee();
  var bugEl = document.getElementById('cs-bug');
  if (bugEl) {
    bugEl.classList.remove('tremble');
    bugEl.classList.add('flee-dash'); // ① 画面外へ ダッシュ（CSS）
  }
  csDust(); // ① 土ぼこり
  csUpdateWarnPop(false);
  csLog(msg);
  csSetButtons(false);
  csFinish(false);
}

/* けっちゃく → フィールドへ もどる */
function csFinish(caught) {
  var cs = G.cs;
  var result = caught
    ? { caught: true, key: cs.key, name: cs.name, pts: cs.pts, mm: cs.mm, big: cs.big }
    : { caught: false, key: cs.key, name: cs.name, pts: 0, mm: cs.mm, big: cs.big };
  // みじかい えんしゅつの あと もどる
  setTimeout(function () { returnToField(result); }, caught ? 1100 : 1000);
}
