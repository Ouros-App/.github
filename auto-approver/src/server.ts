import express from "express";
import { config } from "./config.js";
import { verifyWebhookSignature } from "./github.js";
import { runAutoReview } from "./review.js";

const app = express();
app.use(express.raw({ type: "application/json", limit: "2mb" }));
app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

app.post("/webhooks/github", async (req, res) => {
  const raw = req.body as Buffer;
  const signature = req.header("x-hub-signature-256");
  if (!verifyWebhookSignature(raw, signature)) return res.status(401).json({ error: "invalid webhook signature" });

  const event = req.header("x-github-event");
  if (event !== "issue_comment") return res.status(202).json({ ignored: true });

  let payload: any;
  try { payload = JSON.parse(raw.toString("utf8")); }
  catch { return res.status(400).json({ error: "invalid json" }); }

  if (payload.action !== "created" || !payload.issue?.pull_request) return res.status(202).json({ ignored: true });
  const comment = String(payload.comment?.body ?? "").trim();
  if (comment !== config.COMMAND) return res.status(202).json({ ignored: true });

  const installationId = payload.installation?.id;
  if (!installationId) return res.status(400).json({ error: "missing installation id" });

  const association = String(payload.comment?.author_association ?? "").toUpperCase();
  if (!["OWNER", "MEMBER", "COLLABORATOR"].includes(association)) return res.status(403).json({ error: "comment author is not trusted" });

  const ctx = {
    owner: payload.repository.owner.login,
    repo: payload.repository.name,
    pullNumber: payload.issue.number,
    installationId: Number(installationId)
  };

  res.status(202).json({ accepted: true });
  try { await runAutoReview(ctx); }
  catch (error) { console.error("auto-review failed", { ctx, error }); }
});

app.listen(config.PORT, () => console.log(`Ouros Auto Approver listening on :${config.PORT}`));
