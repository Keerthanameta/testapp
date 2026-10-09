import crypto from "node:crypto";
import express from "express";

const app = express();

// Capture the raw body so the X-Hub-Signature-256 HMAC can be verified.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "vibecode";
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const APP_SECRET = process.env.APP_SECRET;

if (!APP_SECRET) {
  console.warn("WARNING: APP_SECRET not set — webhook signatures NOT verified");
}

// ---------- Signature verification ----------
function verifySignature(req) {
  if (!APP_SECRET) return true; // skipped when no secret is configured
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
    console.error(
      `Verification failed | mode: ${JSON.stringify(mode)} | ` +
      `received token length: ${token?.length} | expected length: ${VERIFY_TOKEN.length} | ` +
      `match: ${token === VERIFY_TOKEN}`
    );
    res.sendStatus(403);
  }
});

// ---------- Receive events (POST) ----------
app.post("/webhook", async (req, res) => {
  if (!verifySignature(req)) {
    console.error("Invalid webhook signature — rejecting");
    return res.sendStatus(403);
  }

  res.sendStatus(200); // ACK immediately

  console.log("Incoming webhook message:", JSON.stringify(req.body, null, 2));

  const value = req.body?.entry?.[0]?.changes?.[0]?.value;

  // ---------- STATUS updates: sent / delivered / read / failed ----------
  const statuses = value?.statuses ?? [];
  if (statuses.length > 0) {
    for (const status of statuses) {
      const ts = new Date(Number(status.timestamp) * 1000).toISOString();
      console.log(
        `STATUS: ${status.status.toUpperCase()} | wamid: ${status.id} | ` +
          `to: ${status.recipient_id} | at: ${ts}`
      );
      if (status.status === "failed") {
        console.error("FAILED DETAILS:", JSON.stringify(status.errors, null, 2));
      }
    }
    return; // status payloads contain no messages
  }

  // ---------- INCOMING messages ----------
  const msg = value?.messages?.[0];
  if (!msg) return;

  const from = msg.from;
  const phoneNumberId = value.metadata.phone_number_id;
  const buttonId = msg.interactive?.button_reply?.id;

  if (buttonId === "more_info_yes") {
    await sendText(phoneNumberId, from,
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
  }

  if (buttonId === "more_info_no") {
    await sendText(phoneNumberId, from,
      "No problem! 👍 Message us any time if you change your mind."
    );
  }
});

// ---------- Health check ----------
app.get("/", (req, res) => {
  res.send("Webhook app is running");
});

// ---------- Helper: send a text message ----------
async function sendText(phoneNumberId, to, body) {
  const url = `https://graph.facebook.com/v26.0/${phoneNumberId}/messages`;
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
  if (!r.ok) console.error("Send failed:", r.status, await r.text());
}

app.listen(PORT, () => {
  console.log(`Your service is live on port ${PORT}`);
});
