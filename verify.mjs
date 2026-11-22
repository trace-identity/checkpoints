#!/usr/bin/env node
// Trace 외부 게시분 독립 검증 스크립트
//
// Node.js 18 이상만 있으면 된다. 추가 패키지는 쓰지 않는다. Trace 서버에는 접속하지 않는다.
// (게시 파일은 이 공개 저장소에서 읽는다. --repo-dir 로 내려받은 사본을 가리킬 수도 있다)
//
//   node verify.mjs 검증자료.json                 검증 화면의 "검증 자료 복사"로 받은 JSON, 또는 내보내기 파일
//   node verify.mjs 검증자료.json --repo-dir .    게시 파일을 네트워크 대신 이 폴더(저장소 사본)에서 읽는다
//   node verify.mjs --self-test                   vectors.json 의 기준값으로 계산식을 확인한다
//
// ── 정규 형식 (Trace 앱 lib/anchor.ts, /about/verify, 이 저장소 README 에 같은 문장으로 적혀 있다) ──
// 1. 문장 지문(content_hash) = sha256(문장의 UTF-8 바이트). 소문자 hex 64자.
// 2. 잎 = sha256( 0x00 한 바이트 ‖ 아래 일곱 줄의 UTF-8 바이트 ).
//    줄 사이는 LF(0x0A) 하나이고 마지막 줄 뒤에는 줄바꿈이 없다.
//      trace-leaf/v1
//      salt          소문자 hex 64자(무작위 32바이트)
//      entry_hash    소문자 hex 64자
//      content_hash  소문자 hex 64자
//      created_at    UTC, YYYY-MM-DDTHH:MM:SS.ffffffZ (마이크로초 6자리)
//      input_method  typed, voice, pasted, ai_chat, ai_assisted, bundle 중 하나
//      seq           앞에 0 을 붙이지 않은 십진수
// 3. 노드 = sha256( 0x01 한 바이트 ‖ 왼쪽 32바이트 ‖ 오른쪽 32바이트 ).
// 4. 하루의 요약값(root): 그 날의 잎을 바이트 오름차순으로 늘어놓고 앞에서부터 둘씩 짝지어 노드를 만든다.
//    짝이 없는 마지막 하나는 그대로 윗단으로 올린다. 하나가 남을 때까지 되풀이한다.
//    잎이 없는 날의 요약값은 sha256(빈 입력) = e3b0c442…b855 이다.
// 5. 포함 증명(path)은 잎에서 요약값까지 가는 길의 형제값 목록이다. 각 단계에서 side 가 "L" 이면
//    sha256(0x01 ‖ 형제 ‖ 현재값), "R" 이면 sha256(0x01 ‖ 현재값 ‖ 형제)를 계산한다.
// 6. 날짜 파일(days/YYYY/YYYY-MM-DD.txt)은 아래 네 줄의 UTF-8 바이트다.
//    모든 줄은 LF(0x0A) 하나로 끝나고 마지막 줄도 LF 로 끝난다. BOM 과 CR 은 없다. hex 는 소문자다.
//      trace-day/v1
//      date:YYYY-MM-DD      한국 시간 기준 날짜
//      root:<소문자 hex 64자>
//      prev:<소문자 hex 64자> 바로 앞 날짜 파일의 sha256. 첫 파일은 0 을 64개 쓴다
// 7. 그 날의 게시값 = sha256(날짜 파일의 바이트 전체). 다음 날 파일의 prev 가 이 값이다.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

export const DEFAULT_REPO = "trace-identity/checkpoints";
export const DEFAULT_BRANCH = "main";
export const EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export const GENESIS_PREV = "0".repeat(64);

const HEX64 = /^[0-9a-f]{64}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const CREATED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

export function sha256Hex(bytes) {
  return sha256(bytes).toString("hex");
}

export function contentHash(content) {
  return sha256Hex(Buffer.from(content, "utf8"));
}

export function leafHash(r) {
  const text = [
    "trace-leaf/v1",
    r.salt,
    r.entry_hash,
    r.content_hash,
    r.created_at,
    r.input_method,
    String(r.seq),
  ].join("\n");
  return sha256Hex(Buffer.concat([Buffer.from([0x00]), Buffer.from(text, "utf8")]));
}

export function nodeHash(left, right) {
  return sha256Hex(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, "hex"), Buffer.from(right, "hex")]));
}

// 소문자 hex 문자열의 사전순은 바이트 오름차순과 같다
function sortLeaves(leaves) {
  return [...leaves].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export function merkleRoot(leaves) {
  if (leaves.length === 0) return EMPTY_ROOT;
  let level = sortLeaves(leaves);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

// 잎 하나의 포함 증명을 만든다 (기준값을 만들 때와 시험에 쓴다)
export function merklePath(leaves, leaf) {
  let level = sortLeaves(leaves);
  let pos = level.indexOf(leaf);
  if (pos < 0) throw new Error("잎이 목록에 없습니다");
  const steps = [];
  while (level.length > 1) {
    if (pos % 2 === 0) {
      if (pos + 1 < level.length) steps.push({ side: "R", hash: level[pos + 1] });
    } else {
      steps.push({ side: "L", hash: level[pos - 1] });
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
    pos = Math.floor(pos / 2);
  }
  return steps;
}

export function proofRoot(leaf, steps) {
  let current = leaf;
  for (const step of steps) {
    if (!step || !HEX64.test(step.hash)) throw new Error("포함 증명의 형제값 형식이 올바르지 않습니다");
    if (step.side === "L") current = nodeHash(step.hash, current);
    else if (step.side === "R") current = nodeHash(current, step.hash);
    else throw new Error("포함 증명의 side 는 L 또는 R 이어야 합니다");
  }
  return current;
}

export function dayFileText(day, root, prev) {
  return `trace-day/v1\ndate:${day}\nroot:${root}\nprev:${prev}\n`;
}

export function dayValue(day, root, prev) {
  return sha256Hex(Buffer.from(dayFileText(day, root, prev), "utf8"));
}

// 날짜 파일의 바이트를 읽어 뜻을 꺼낸다. 형식이 한 글자라도 다르면 null.
export function parseDayFile(bytes) {
  const text = Buffer.from(bytes).toString("utf8");
  const m = /^trace-day\/v1\ndate:(\d{4}-\d{2}-\d{2})\nroot:([0-9a-f]{64})\nprev:([0-9a-f]{64})\n$/.exec(text);
  if (!m) return null;
  return { day: m[1], root: m[2], prev: m[3], value: sha256Hex(Buffer.from(bytes)) };
}

export function dayFilePath(day) {
  return `days/${day.slice(0, 4)}/${day}.txt`;
}

export function nextDay(day) {
  const [y, m, d] = day.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d + 1)).toISOString().slice(0, 10);
}

// created_at(UTC) 의 한국 날짜. 한국 시간은 UTC+9 이고 서머타임이 없다.
export function kstDayOf(createdAt) {
  const ms = Date.parse(createdAt.slice(0, 19) + "Z");
  return new Date(ms + 9 * 3600 * 1000).toISOString().slice(0, 10);
}

// ── 아래는 명령줄 실행 ──────────────────────────────────────────────────────────

async function readDayFile(day, opts) {
  const rel = dayFilePath(day);
  if (opts.repoDir) {
    try {
      return await readFile(path.join(opts.repoDir, rel));
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
  }
  const url = `https://raw.githubusercontent.com/${opts.repo}/${opts.branch}/${rel}`;
  const res = await fetch(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`게시 파일을 읽지 못했습니다 (${res.status}): ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

function checkRecordShape(r) {
  const problems = [];
  if (!HEX64.test(r.salt ?? "")) problems.push("salt");
  if (!HEX64.test(r.entry_hash ?? "")) problems.push("entry_hash");
  if (!HEX64.test(r.content_hash ?? "")) problems.push("content_hash");
  if (!CREATED_AT.test(r.created_at ?? "")) problems.push("created_at");
  if (typeof r.input_method !== "string" || r.input_method === "") problems.push("input_method");
  if (!/^[1-9]\d*$/.test(String(r.seq))) problems.push("seq");
  if (!DAY.test(r.day ?? "")) problems.push("day");
  if (!Array.isArray(r.path)) problems.push("path");
  return problems;
}

// 기록 하나를 검증한다. 결과: { ok, lines[] }
export async function verifyRecord(r, opts) {
  const lines = [];
  const fail = (msg) => {
    lines.push(`  ✕ ${msg}`);
    return { ok: false, lines };
  };

  const problems = checkRecordShape(r);
  if (problems.length > 0) return fail(`검증 자료의 형식이 올바르지 않습니다: ${problems.join(", ")}`);

  if (typeof r.content === "string") {
    if (contentHash(r.content) !== r.content_hash) return fail("문장의 sha256 이 content_hash 와 다릅니다");
    lines.push("  ✓ 문장의 sha256 = content_hash");
  } else {
    lines.push("  - 문장이 없어(삭제된 기록) content_hash 는 주어진 값을 그대로 썼습니다");
  }

  const leaf = leafHash(r);
  let root;
  try {
    root = proofRoot(leaf, r.path);
  } catch (e) {
    return fail(e.message);
  }
  lines.push(`  ✓ 잎 ${leaf.slice(0, 16)}… 에서 계산한 요약값 ${root.slice(0, 16)}…`);

  const bytes = await readDayFile(r.day, opts);
  if (bytes === null) return fail(`${r.day} 의 게시 파일이 저장소에 없습니다 (${dayFilePath(r.day)})`);
  const file = parseDayFile(bytes);
  if (!file) return fail(`${dayFilePath(r.day)} 의 형식이 올바르지 않습니다`);
  if (file.day !== r.day) return fail(`게시 파일 안의 날짜(${file.day})가 파일 이름과 다릅니다`);
  if (file.root !== root) return fail(`게시된 요약값과 다릅니다 (게시 ${file.root.slice(0, 16)}…)`);
  lines.push(`  ✓ ${dayFilePath(r.day)} 의 root 와 같음`);

  const written = kstDayOf(r.created_at);
  if (written === r.day) {
    lines.push(`  ✓ 작성일(한국 시간 ${written}) = 게시분 날짜`);
  } else if (written < r.day) {
    lines.push(`  ! 작성일(한국 시간 ${written})이 게시분 날짜(${r.day})보다 앞입니다.`);
    lines.push("    게시된 값으로 확인되는 것은 게시분 날짜 이후 바뀌지 않았다는 것뿐입니다.");
  } else {
    return fail(`작성일(한국 시간 ${written})이 게시분 날짜(${r.day})보다 뒤입니다`);
  }

  const next = nextDay(r.day);
  const nextBytes = await readDayFile(next, opts);
  if (nextBytes === null) {
    lines.push(`  - 다음 날(${next}) 파일이 아직 없어 이어짐은 확인하지 않았습니다`);
  } else {
    const nextFile = parseDayFile(nextBytes);
    if (!nextFile || nextFile.prev !== file.value) return fail(`다음 날(${next}) 파일의 prev 가 이 파일의 sha256 과 다릅니다`);
    lines.push(`  ✓ 다음 날(${next}) 파일의 prev = 이 파일의 sha256`);
  }

  return { ok: true, lines, day: r.day };
}

export function selfTest(vectors) {
  const problems = [];
  const eq = (name, got, want) => {
    if (JSON.stringify(got) !== JSON.stringify(want)) problems.push(`${name}: 계산값이 기준값과 다릅니다`);
  };
  eq("empty_root", merkleRoot([]), vectors.empty_root);
  for (const set of vectors.sets) {
    const leaves = set.records.map((r) => leafHash(r));
    set.records.forEach((r, i) => {
      if (typeof r.content === "string") eq(`${set.name} content_hash ${i + 1}`, contentHash(r.content), r.content_hash);
    });
    eq(`${set.name} leaves`, leaves, set.leaves);
    eq(`${set.name} root`, merkleRoot(leaves), set.root);
    eq(`${set.name} root (역순 입력)`, merkleRoot([...leaves].reverse()), set.root);
    leaves.forEach((leaf, i) => {
      eq(`${set.name} path ${i + 1}`, merklePath(leaves, leaf), set.paths[i]);
      eq(`${set.name} proof ${i + 1}`, proofRoot(leaf, set.paths[i]), set.root);
    });
  }
  for (const d of vectors.days) {
    eq(`day ${d.day} text`, dayFileText(d.day, d.root, d.prev), d.text);
    eq(`day ${d.day} value`, dayValue(d.day, d.root, d.prev), d.value);
    eq(`day ${d.day} parse`, parseDayFile(Buffer.from(d.text, "utf8")), { day: d.day, root: d.root, prev: d.prev, value: d.value });
  }
  return problems;
}

function parseArgs(argv) {
  const opts = { repo: DEFAULT_REPO, branch: DEFAULT_BRANCH, repoDir: null, file: null, selfTest: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--self-test") opts.selfTest = true;
    else if (a === "--repo-dir") opts.repoDir = argv[++i];
    else if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--branch") opts.branch = argv[++i];
    else if (!a.startsWith("--") && !opts.file) opts.file = a;
    else throw new Error(`알 수 없는 인자: ${a}`);
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.selfTest) {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const vectors = JSON.parse(await readFile(path.join(here, "vectors.json"), "utf8"));
    const problems = selfTest(vectors);
    if (problems.length > 0) {
      console.error(problems.join("\n"));
      process.exit(1);
    }
    console.log("기준값과 모두 같습니다.");
    return;
  }

  if (!opts.file) {
    console.error("사용법: node verify.mjs 검증자료.json [--repo-dir 폴더]   또는   node verify.mjs --self-test");
    process.exit(2);
  }

  const input = JSON.parse(await readFile(opts.file, "utf8"));
  // 검증 화면에서 복사한 자료(trace-proof/v1) 또는 내보내기 파일(external_anchor 안에 같은 형식)
  const proof = input.format === "trace-proof/v1" ? input : input.external_anchor;
  if (!proof || proof.format !== "trace-proof/v1" || !Array.isArray(proof.records)) {
    console.error("trace-proof/v1 형식의 검증 자료가 아닙니다.");
    process.exit(2);
  }
  if (!opts.repoDir && typeof proof.repo === "string" && proof.repo !== opts.repo) {
    console.log(`주의: 검증 자료가 가리키는 저장소(${proof.repo})가 아니라 ${opts.repo} 에서 게시 파일을 읽습니다.`);
  }

  let failed = 0;
  const days = new Set();
  for (const r of proof.records) {
    console.log(`#${r.seq} (${r.created_at})`);
    let result;
    try {
      result = await verifyRecord(r, opts);
    } catch (e) {
      result = { ok: false, lines: [`  ✕ ${e.message}`] };
    }
    console.log(result.lines.join("\n"));
    if (result.ok) days.add(result.day);
    else failed++;
  }

  console.log("");
  if (failed > 0) {
    console.log(`검증 실패 ${failed}건 / 전체 ${proof.records.length}건`);
    process.exit(1);
  }
  console.log(`${proof.records.length}건 모두 게시된 요약값과 맞습니다.`);
  console.log("");
  console.log("남은 확인: 게시 파일이 그 날짜 무렵에 실제로 있었는지는 OpenTimestamps 증명으로 봅니다.");
  for (const day of [...days].sort()) {
    console.log(`  ots verify ${dayFilePath(day)}.ots     (또는 opentimestamps.org 에 .txt 와 .ots 를 함께 올린다)`);
  }
  console.log("  표시되는 비트코인 블록 날짜가 게시분 날짜와 가까운지 확인하세요.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
