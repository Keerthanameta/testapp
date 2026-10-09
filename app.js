import crypto from "crypto";
import express from "express";

const app = express();

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "vibecode";
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const APP_SECRET = process.env.APP_SECRET;
const GRAPH_VERSION = process.env.GRAPH_VERSION || "v26.0";

if (!WHATSAPP_TOKEN) {
  console.error("FATAL: WHATSAPP_TOKEN is not set");
  process.exit(1);
}
if (!APP_SECRET) {
  console.warn("WARNING: APP_SECRET not set — webhook signatures will NOT be verified");
}

// Capture the raw body so we can verify the X-Hub-Signature-256 HMAC.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ---------- Signature verification ----------
function verifySignature(req) {
  if (!APP_SECRET) return true; // skipped when no secret configured
  const header = req.get("x-hub-signature-256");
  if (!header || !req.rawBody) return false;

  const expected =
    "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");

  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- Webhook verification (GET) ----------
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("WEBHOOK VERIFIED");
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// ---------- Dedupe (webhook retries can replay the same wamid) ----------
const seenIds = new Map(); // id -> timestamp
const DEDUPE_TTL_MS = 10 * 60 * 1000;

function alreadyHandled(id) {
  if (!id) return false;
  const now = Date.now();
  for (const [key, ts] of seenIds) {
    if (now - ts > DEDUPE_TTL_MS) seenIds.delete(key);
  }
  if (seenIds.has(id)) return true;
  seenIds.set(id, now);
  return false;
}

// ---------- Receive events (POST) ----------
app.post("/webhook", async (req, res) => {
  if (!verifySignature(req)) {
    console.error("Invalid webhook signature — rejecting");
    return res.sendStatus(403);
  }

  res.sendStatus(200); // ACK immediately

  try {
    console.log("Incoming webhook:", JSON.stringify(req.body, null, 2));

    const entries = req.body?.entry ?? [];
    for (const entry of entries) {
      for (const change of entry?.changes ?? []) {
        const value = change?.value;
        if (!value) continue;

        // ---------- STATUS updates ----------
        for (const status of value.statuses ?? []) {
          handleStatus(status);
        }

        // ---------- INCOMING messages ----------
        for (const msg of value.messages ?? []) {
          await handleMessage(msg, value);
        }
      }
    }
  } catch (err) {
    console.error("Webhook handler error:", err);
  }
});

function handleStatus(status) {
  const ts = new Date(Number(status.timestamp) * 1000).toISOString();
  console.log(
    `STATUS: ${String(status.status).toUpperCase()} | wamid: ${status.id} | ` +
      `to: ${status.recipient_id} | at: ${ts}`
  );
  if (status.status === "failed") {
    console.error("FAILED DETAILS:", JSON.stringify(status.errors, null, 2));
  }
}

async function handleMessage(msg, value) {
  if (alreadyHandled(msg.id)) {
    console.log(`Skipping duplicate message ${msg.id}`);
    return;
  }

  const from = msg.from;
  const phoneNumberId = value?.metadata?.phone_number_id;
  if (!from || !phoneNumberId) {
    console.error("Missing sender or phone_number_id; skipping");
    return;
  }

  // Interactive buttons -> interactive.button_reply.id
  // Template quick replies -> button.payload
  const buttonId = msg.interactive?.button_reply?.id ?? msg.button?.payload;

  switch (buttonId) {
    case "more_info_yes":
      await sendText(
        phoneNumberId,
        from,
        "Here's a quick overview of Meta 🌐\n\n" +
          "Meta builds technologies that help people connect, find communities and grow businesses.\n\n" +
          "📱 Our apps\n" +
          "• Facebook — connect with friends and communities\n" +
          "• Instagram — share photos, reels and stories\n" +
          "• WhatsApp — private, secure messaging\n" +
          "• Messenger — chat, calls and video\n" +
          "• Threads — text-based conversations\n\n" +
          "🥽 Beyond apps\n" +
          "• Meta Quest — virtual and mixed reality\n" +
          "• Ray-Ban Meta glasses — AI-powered eyewear\n" +
          "• Meta AI — our AI assistant"
      );
      return;

    case "more_info_no":
      await sendText(
        phoneNumberId,
        from,
        "No problem! 👍 Message us any time if you change your mind."
      );
      return;
  }

  // Fallback for plain text / unknown input
  if (msg.type === "text") {
    await sendText(
      phoneNumberId,
      from,
      "Thanks for your message! Reply with a button option, or ask us anything."
    );
  } else {
    console.log(`Unhandled message type: ${msg.type}`);
  }
}

// ---------- Health check ----------
app.get("/", (_req, res) => {
  res.send("Webhook app is running");
});

// ---------- Helper: send a text message ----------
async function sendText(phoneNumberId, to, body) {
  const url = `https://graph.facebook.com/${GRAPH_VERSION}/${phoneNumberId}/messages`;

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${WHATSAPP_TOKEN}`,
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to,
        type: "text",
        text: { body },
      }),
    });

    if (!r.ok) {
      console.error("Send failed:", r.status, await r.text());
    }
  } catch (err) {
    console.error("Send threw:", err);
  }
}

app.listen(PORT, () => {
  console.log(`Your service is live on port ${PORT}`);
});
