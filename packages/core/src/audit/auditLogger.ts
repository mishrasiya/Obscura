import { AuditEvent, AuditSink, EntityType } from "../types.js";

/**
 * Default in-memory audit sink. Stores a bounded ring buffer of events for
 * inspection/export. Events never contain raw sensitive values - only entity
 * type counts - making them safe to forward to centralized logging/SIEM
 * systems in enterprise deployments.
 */
export class InMemoryAuditSink implements AuditSink {
  private events: AuditEvent[] = [];

  constructor(private readonly maxEvents = 10_000) {}

  record(event: AuditEvent): void {
    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }
  }

  getEvents(): AuditEvent[] {
    return [...this.events];
  }
}

/** Builds an {@link AuditEvent} from a set of detected (or restored) entities. */
export function buildAuditEvent(
  requestId: string,
  action: AuditEvent["action"],
  entities: { type: EntityType | string }[]
): AuditEvent {
  const entityCounts: AuditEvent["entityCounts"] = {};
  for (const entity of entities) {
    entityCounts[entity.type] = (entityCounts[entity.type] ?? 0) + 1;
  }
  return {
    requestId,
    timestamp: Date.now(),
    action,
    entityCounts,
    totalEntities: entities.length,
  };
}
