export type AttributeDiff = {
  added: Array<{ key: string; value: string }>;
  removed: Array<{ key: string; value: string }>;
  changed: Array<{ key: string; before: string; after: string }>;
};

export function diffAttributes(
  beforeMap: Map<string, string>,
  afterMap: Map<string, string>,
): AttributeDiff {
  const added: AttributeDiff['added'] = [];
  const removed: AttributeDiff['removed'] = [];
  const changed: AttributeDiff['changed'] = [];

  for (const [key, value] of beforeMap.entries()) {
    if (!afterMap.has(key)) {
      removed.push({ key, value });
      continue;
    }
    const nextValue = afterMap.get(key);
    if (nextValue !== value && nextValue !== undefined) {
      changed.push({ key, before: value, after: nextValue });
    }
  }

  for (const [key, value] of afterMap.entries()) {
    if (!beforeMap.has(key)) {
      added.push({ key, value });
    }
  }

  added.sort((a, b) => a.key.localeCompare(b.key));
  removed.sort((a, b) => a.key.localeCompare(b.key));
  changed.sort((a, b) => a.key.localeCompare(b.key));

  return { added, removed, changed };
}
