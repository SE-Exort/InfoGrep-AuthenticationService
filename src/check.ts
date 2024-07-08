import { z } from "zod";
import { app } from "./index";
import { sessions } from "./login";

const CheckParams = z.object({
  sessionToken: z.string(),
});

app.post("/check", async (req, res) => {
  const parseResult = CheckParams.safeParse(req.body);
  if (!parseResult.success) {
    res.send({ error: true, status: "INVALID_SESSION" });
    return;
  }
  const params = parseResult.data;

  let sessionExists = false;
  let userId = '';

  for (const [id, tokens] of sessions.entries()) {
    if (tokens.has(params.sessionToken)) {
      sessionExists = true;
      userId = id;
      break;
    }
  }

  if (sessionExists) {
    // give the other services the authenticated user's username as unique ID across all services
    res.send({ status: "SESSION_AUTHENTICATED", data: {
      id: userId
    }});
  } else {
    res.send({ error: true, status: "INVALID_SESSION" });
  }
});

export { sessions };
