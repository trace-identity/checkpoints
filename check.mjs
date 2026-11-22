#!/usr/bin/env node
// 이 저장소의 게시 파일이 온전한지 살핀다. 비밀값이 필요 없고, Node.js 18 이상만 있으면 된다.
// .github/workflows/check.yml 이 매일 돌리고, 누구나 저장소를 내려받아 직접 돌릴 수 있다: node check.mjs
//
// 살피는 것
//   1. days/ 아래 날짜 파일의 형식(정규 형식 6번), 파일 이름과 안의 날짜, 연도 폴더
//   2. 날짜가 빠짐 없이 이어지고, 각 파일의 prev 가 앞 파일의 sha256 인지 (첫 파일은 0 이 64개)
//   3. 어제(한국 시간) 파일이 올라와 있는지 (새벽 3시 전에는 그제까지)
//   4. 시각 증명(.ots): 하루 넘은 날짜 파일마다 있는지, 그 파일의 sha256 을 가리키는지,
//      7일 넘은 것은 비트코인 블록 증명이 붙었는지
// 문제가 하나라도 있으면 종료 코드 1 로 끝난다.

import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { GENESIS_PREV, nextDay, parseDayFile } from "./verify.mjs";

const OTS_MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
const BITCOIN_TAG = Buffer.from("0588960d73d71901", "hex");
const OTS_REQUIRED_AFTER_DAYS = 1;
const OTS_COMPLETE_AFTER_DAYS = 7;

function addDays(day, n) {
  const [y, m, d] = day.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d + n)).toISOString().slice(0, 10);
}

// 한국 시간(UTC+9) 기준 날짜. 새벽 게시가 끝날 시간을 주려고 3시간을 뺀다.
function expectedLatestDay(now = Date.now()) {
  const kst = new Date(now + 9 * 3600 * 1000 - 3 * 3600 * 1000).toISOString().slice(0, 10);
  return addDays(kst, -1);
}

export async function checkRepo(root, now = Date.now()) {
  const problems = [];
  const notes = [];
  const daysDir = path.join(root, "days");

  let years = [];
  try {
    years = (await readdir(daysDir, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }

  const files = new Map(); // day → { file, ots }
  for (const year of years) {
    if (!/^\d{4}$/.test(year)) {
      problems.push(`days/${year}: 연도 폴더가 아닙니다`);
      continue;
    }
    for (const name of (await readdir(path.join(daysDir, year))).sort()) {
      const m = /^(\d{4}-\d{2}-\d{2})\.txt(\.ots)?$/.exec(name);
      if (!m || m[1].slice(0, 4) !== year) {
        problems.push(`days/${year}/${name}: 여기 있을 파일이 아닙니다`);
        continue;
      }
      const item = files.get(m[1]) ?? {};
      const bytes = await readFile(path.join(daysDir, year, name));
      if (m[2]) item.ots = bytes;
      else item.file = bytes;
      files.set(m[1], item);
    }
  }

  const days = [...files.keys()].sort();
  if (days.length === 0) {
    notes.push("아직 게시된 날짜 파일이 없습니다.");
    return { problems, notes, days: 0 };
  }

  const today = expectedLatestDay(now);
  let prevDay = null;
  let prevValue = GENESIS_PREV;
  let anyOts = false;
  for (const day of days) {
    const { file, ots } = files.get(day);
    if (!file) {
      problems.push(`${day}: 시각 증명만 있고 날짜 파일이 없습니다`);
      continue;
    }
    const parsed = parseDayFile(file);
    if (!parsed) {
      problems.push(`${day}: 날짜 파일의 형식이 정규 형식과 다릅니다`);
      continue;
    }
    if (parsed.day !== day) problems.push(`${day}: 파일 안의 날짜(${parsed.day})가 파일 이름과 다릅니다`);
    if (prevDay !== null && day !== nextDay(prevDay)) problems.push(`${day}: ${nextDay(prevDay)} 파일이 빠져 있습니다`);
    if (parsed.prev !== prevValue) problems.push(`${day}: prev 가 앞 파일의 sha256 과 다릅니다`);
    prevDay = day;
    prevValue = parsed.value;

    if (ots) {
      anyOts = true;
      const digestOk =
        ots.length > 65 && ots.subarray(0, 31).equals(OTS_MAGIC) && ots[31] === 0x01 && ots[32] === 0x08 &&
        ots.subarray(33, 65).toString("hex") === parsed.value;
      if (!digestOk) problems.push(`${day}: 시각 증명이 이 날짜 파일의 sha256 을 가리키지 않습니다`);
      else if (day <= addDays(today, -OTS_COMPLETE_AFTER_DAYS) && !ots.includes(BITCOIN_TAG)) {
        problems.push(`${day}: 시각 증명이 ${OTS_COMPLETE_AFTER_DAYS}일 넘게 확정되지 않았습니다 (ots upgrade 로 갱신해 올려야 합니다)`);
      }
    }
  }

  if (anyOts) {
    for (const day of days) {
      if (!files.get(day).ots && day <= addDays(today, -OTS_REQUIRED_AFTER_DAYS)) problems.push(`${day}: 시각 증명(.ots)이 없습니다`);
    }
  } else {
    notes.push("시각 증명(.ots)이 하나도 없습니다. 시각 증명을 꺼 둔 상태로 봅니다.");
  }

  const latest = days[days.length - 1];
  if (latest < today) problems.push(`마지막 게시가 ${latest} 입니다. ${today} 파일이 올라오지 않았습니다`);

  return { problems, notes, days: days.length, first: days[0], latest };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const root = process.argv[2] ?? path.dirname(fileURLToPath(import.meta.url));
  const result = await checkRepo(root);
  result.notes.forEach((n) => console.log(`참고: ${n}`));
  if (result.days > 0) console.log(`날짜 파일 ${result.days}개 (${result.first} ~ ${result.latest})`);
  if (result.problems.length > 0) {
    result.problems.forEach((p) => console.error(`문제: ${p}`));
    process.exit(1);
  }
  console.log("이상 없음");
}
