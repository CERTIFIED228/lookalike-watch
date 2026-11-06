// IndexedDB storage for the phishing feeds. ~400k entries is too much to
// load into memory every time the service worker wakes up, but IndexedDB
// lets us look up a single key in a millisecond.

import { FEEDS } from "./feeds.js";

const DB_NAME = "lookalike-watch";
const STORE = "phish";
const SEP = "\t";

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function done(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Swap one feed's entries for a new set, in a single transaction. */
export async function replaceFeed(feedId, keys) {
  const db = await open();
  const tx = db.transaction(STORE, "readwrite");
  const store = tx.objectStore(STORE);
  store.delete(IDBKeyRange.bound(`${feedId}${SEP}`, `${feedId}${SEP}￿`));
  for (const key of keys) store.put(1, `${feedId}${SEP}${key}`);
  await done(tx);
  db.close();
}

/** First feed that lists any of these keys, or null. */
export async function findFeedHit(keys) {
  if (!keys.length) return null;
  const db = await open();
  const store = db.transaction(STORE, "readonly").objectStore(STORE);
  const lookups = FEEDS.flatMap((feed) =>
    keys.map((key) => new Promise((resolve) => {
      const req = store.count(`${feed.id}${SEP}${key}`);
      req.onsuccess = () => resolve(req.result ? feed : null);
      req.onerror = () => resolve(null);
    })),
  );
  const hit = (await Promise.all(lookups)).find(Boolean);
  db.close();
  return hit ? { source: hit.name } : null;
}
