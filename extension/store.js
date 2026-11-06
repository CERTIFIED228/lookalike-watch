// IndexedDB storage for the phishing feeds. ~400k entries is too much to
// load into memory every time the service worker wakes up, but IndexedDB
// lets us look up a single key in a millisecond.
//
// Each download is written as a new "generation" in small chunks, and only
// switched to once it's complete. A worker that gets stopped halfway leaves
// the old list working, and page lookups never wait behind a huge write.

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

/** Write keys under `generation`, a chunk per transaction. */
export async function writeGeneration(generation, keys, { chunkSize = 20_000, between } = {}) {
  const db = await open();
  try {
    for (let i = 0; i < keys.length; i += chunkSize) {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      for (const key of keys.slice(i, i + chunkSize)) store.put(1, `${generation}${SEP}${key}`);
      await done(tx);
      if (between) await between();
    }
  } finally {
    db.close();
  }
}

/** Remove every generation of a feed except the one in use. */
export async function deleteOtherGenerations(feedId, keep) {
  const db = await open();
  const tx = db.transaction(STORE, "readwrite");
  const store = tx.objectStore(STORE);
  const all = IDBKeyRange.bound(`${feedId}@`, `${feedId}@￿`);
  if (!keep) {
    store.delete(all);
  } else {
    store.delete(IDBKeyRange.bound(`${feedId}@`, `${keep}${SEP}`, false, true));
    store.delete(IDBKeyRange.bound(`${keep}${SEP}￿`, `${feedId}@￿`, true, false));
  }
  await done(tx);
  db.close();
}

/**
 * First feed that lists any of these keys, or null.
 * `generations` is [{ generation, name }] for the lists currently in use.
 */
export async function findFeedHit(keys, generations) {
  if (!keys.length || !generations.length) return null;
  const db = await open();
  const store = db.transaction(STORE, "readonly").objectStore(STORE);
  const lookups = generations.flatMap(({ generation, name }) =>
    keys.map((key) => new Promise((resolve) => {
      const req = store.count(`${generation}${SEP}${key}`);
      req.onsuccess = () => resolve(req.result ? name : null);
      req.onerror = () => resolve(null);
    })),
  );
  const hit = (await Promise.all(lookups)).find(Boolean);
  db.close();
  return hit ? { source: hit } : null;
}
