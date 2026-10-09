import express from "express";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "vibecode";

function makeWebhook(name) {
  // GET = Meta's one-time handshake
  app.get('/${name}', (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];
    if (mode === "subscribe" && token === VERIFY_TOKEN) {
      console.log('WEBHOOK VERIFIED -> /${name}');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  });

  // POST = the real webhook events
  app.post('/${name}', (req, res) => {
    console.log('\n========== /${name} ==========');
    console.log(JSON.stringify(req.body, null, 2));
    res.sendStatus(200);
  });
}

makeWebhook("webhook");       // 🔘 APP level
makeWebhook("waba");          // 🟢 WABA level
makeWebhook("phonenumber");   // 🔵 PHONE level

app.get("/", (req, res) => {
  res.send("Webhook app is running");
});

app.listen(PORT, () => {
  console.log('Your service is live on port ${PORT}');
});
