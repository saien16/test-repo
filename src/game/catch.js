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
  var sizeF = 0.85 + U.rnd() * 0.5;
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
    warned: false, // 「にげそう!」予告ずみか
    graced: false, // 予告の 1かい ゆうよを つかったか
  };

  G.player.busy = true;
  buildCatchUI();
  csLog('🌿 ガサッ…! <b>' + bug.name + '</b>を みつけた！（' + CONFIG.START_DIST + 'm さき・およそ ' + mm + 'mm）');
  Sound.sfx.select();
  showScreen('catch-screen');

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
      '<div class="cs-alert-label"><span>けいかい</span><span id="cs-alert-num">0%</span></div>' +
      '<div class="cs-alert-bar"><div class="cs-alert-fill" id="cs-alert-fill"></div></div>' +
    '</div>' +
    '<div class="cs-arena" id="cs-arena">' +
      '<div class="cs-bug" id="cs-bug">' + bugSprite(cs.key, bugPx) + '</div>' +
      '<div class="cs-hunter">🥅</div>' +
    '</div>' +
    '<div class="cs-log" id="cs-log"></div>' +
    '<div class="cs-actions">' +
      '<button class="cs-btn approach" id="cs-approach">ちかよる<small>2m すすむ・ばれやすい</small></button>' +
      '<button class="cs-btn sneak" id="cs-sneak">そっと<small>1m すすむ・しずか</small></button>' +
      '<button class="cs-btn wait" id="cs-wait">まつ<small>けいかいを さげる</small></button>' +
      '<button class="cs-btn net" id="cs-net">あみを ふる！<small id="cs-net-acc"></small></button>' +
    '</div>';

  document.getElementById('cs-approach').onclick = function () { csAct('approach'); };
  document.getElementById('cs-sneak').onclick = function () { csAct('sneak'); };
  document.getElementById('cs-wait').onclick = function () { csAct('wait'); };
  document.getElementById('cs-net').onclick = function () { csSwing(); };
}

/* むしの 見た目サイズ(px)。個体差で すこし おおきく */
function csBugPx() {
  var f = U.clamp(G.cs.sizeF, 0.85, 1.35);
  return Math.round(CS_BUG_PX_MIN + (CS_BUG_PX_MAX - CS_BUG_PX_MIN) * ((f - 0.85) / 0.5));
}

/* ログ欄に じっきょうを だす */
function csLog(html) {
  var el = document.getElementById('cs-log');
  if (el) el.innerHTML = html;
}

/* きょり(m) → あみの 実効 命中りつ(0〜1) */
function csHitRate() {
  var d = U.clamp(Math.round(G.cs.dist), 0, 2);
  var base = CONFIG.NET_HIT[d] != null ? CONFIG.NET_HIT[d] : 0.3;
  // 近接ボーナス: 0mで +0.12 / 1mで +0.06 / 2mで +0
  var bonus = (2 - d) * 0.06;
  return U.clamp(base + bonus, 0.05, 0.97);
}

/* 画面（きょり・ゲージ・ボタン・むし位置）を かきなおす */
function csRender() {
  var cs = G.cs;
  if (!cs) return;
  var a = Math.round(cs.alert);
  var aClamp = Math.min(100, Math.max(0, a));

  var dist = document.getElementById('cs-dist');
  if (dist) dist.textContent = cs.dist <= 1 ? '🎯 とどく！' : 'あと ' + cs.dist + 'm';

  var fill = document.getElementById('cs-alert-fill');
  if (fill) {
    fill.style.width = aClamp + '%';
    fill.classList.toggle('warn', aClamp >= 70 && aClamp < 90);
    fill.classList.toggle('danger', aClamp >= 90);
  }
  var num = document.getElementById('cs-alert-num');
  if (num) num.textContent = aClamp + '%';

  var arena = document.getElementById('cs-arena');
  if (arena) arena.classList.toggle('warn-glow', aClamp >= 70);

  // むしの 横位置: きょりが ちかいほど 左(プレイヤー)へ よる
  var bugEl = document.getElementById('cs-bug');
  if (bugEl) {
    var t = U.clamp(cs.dist / CONFIG.START_DIST, 0, 1); // 0=ちかい 1=とおい
    bugEl.style.right = (6 + t * 30) + '%';
  }

  // あみ命中りつ ひょうじ
  var accEl = document.getElementById('cs-net-acc');
  if (accEl) accEl.textContent = 'めいちゅう やく ' + Math.round(csHitRate() * 100) + '%';

  // ボタン ゆうこう／むこう
  csSetButtons(!cs.busy && !cs.over);
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

/* あみを ふる */
function csSwing() {
  var cs = G.cs;
  if (!cs || cs.over || cs.busy) return;
  cs.busy = true;
  csSetButtons(false);
  Sound.sfx.select();

  var rate = csHitRate();
  csLog('🥅 えいっ！ あみを ふった！');

  setTimeout(function () {
    if (!cs || cs.over) return;
    if (U.chance(rate)) {
      // めいちゅう → ほかく せいこう
      cs.over = true;
      Sound.sfx.catch();
      if (cs.big) Sound.sfx.big();
      var bugEl = document.getElementById('cs-bug');
      if (bugEl) bugEl.style.transform = 'scale(.2)';
      csLog('🎉 やったー！ <b>' + cs.name + '</b>（' + cs.mm + 'mm）を つかまえた！ +' + cs.pts + 'てん'
        + (cs.big ? '（でかボーナス ×2！）' : ''));
      csFinish(true);
    } else {
      // はずれ → けいかい大up
      Sound.sfx.miss();
      cs.alert = U.clamp(cs.alert + 35, 0, 200);
      var bugEl2 = document.getElementById('cs-bug');
      if (bugEl2) { bugEl2.style.transform = 'translateX(-6px)'; setTimeout(function(){ if(bugEl2) bugEl2.style.transform=''; }, 200); }
      csRender();
      if (cs.alert >= CONFIG.ALERT_FLEE) {
        csLog('😖 はずした…！ ' + cs.name + 'が おどろいた！');
        setTimeout(function () { csFlee('💨 ' + cs.name + 'は にげてしまった！'); }, 600);
        return;
      }
      if (cs.alert >= CONFIG.ALERT_WARN && !cs.warned) {
        cs.warned = true; cs.graced = true;
        Sound.sfx.warn();
        csShowWarnPop();
      }
      csLog('😖 はずした！ ' + cs.name + 'が けいかい している…');
      cs.busy = false;
      csRender();
    }
  }, 460);
}

/* にげられた */
function csFlee(msg) {
  var cs = G.cs;
  if (!cs || cs.over) { /* over=trueでも 演出ずみなら そのまま */ }
  if (cs) cs.over = true;
  Sound.sfx.flee();
  var bugEl = document.getElementById('cs-bug');
  if (bugEl) { bugEl.style.transition = 'right .5s ease, opacity .5s'; bugEl.style.right = '-30%'; bugEl.style.opacity = '0'; }
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
