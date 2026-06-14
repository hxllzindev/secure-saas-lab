const DETECTIONS = {
  login_failed: {
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    severity: "medium"
  },
  login_blocked: {
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    severity: "high"
  },
  invoice_access_denied: {
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
    severity: "high"
  },
  note_created_vulnerable: {
    techniqueId: "T1059.007",
    techniqueName: "JavaScript/JScript",
    severity: "medium"
  }
};

export function enrichAuditEvent(event) {
  const key = event.action === "note_created" && event.mode === "vulnerable"
    ? "note_created_vulnerable"
    : event.action;
  const detection = DETECTIONS[key] ?? {};
  return {
    ...event,
    ...detection,
    severity: event.severity ?? detection.severity ?? "info"
  };
}
