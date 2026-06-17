import { DetectedEntity } from "./types.js";

/**
 * Merges entity lists from multiple detectors into a single non-overlapping,
 * sorted list. Lists are given in priority order (earlier = higher
 * priority): on overlap, an earlier list's match wins.
 *
 * Default priority: dictionary (known-value lookups) > regex (structured
 * patterns) > NER (free-form names/orgs/locations). Dictionary and regex
 * matches carry confidence 1.0 and target exact/structured values, so an
 * NER guess overlapping either should not fragment them.
 */
export function mergeEntities(...entityLists: DetectedEntity[][]): DetectedEntity[] {
  const all = entityLists.flatMap((entities, priority) => entities.map((entity) => ({ entity, priority })));

  all.sort((a, b) => {
    if (a.entity.start !== b.entity.start) return a.entity.start - b.entity.start;
    if (a.priority !== b.priority) return a.priority - b.priority;
    const lenA = a.entity.end - a.entity.start;
    const lenB = b.entity.end - b.entity.start;
    return lenB - lenA;
  });

  const selected: DetectedEntity[] = [];
  let lastEnd = -1;
  for (const { entity } of all) {
    if (entity.start >= lastEnd) {
      selected.push(entity);
      lastEnd = entity.end;
    }
  }

  return selected;
}
