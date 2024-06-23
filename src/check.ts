import { z } from "zod";
import { app } from "./index";
import { sessions } from "login";

const CheckParams = z.object({
  sessionToken: z.string(),
});

app.post("/check", async (req, res) => {
  const params = CheckParams.parse(req.body);

  // todo: check session using the sessions hashmap

  let sessionExists = false;
  if (sessionExists) {
    // give the other services the authenticated user's username as unique ID across all services
    res.send({ status: "SESSION_AUTHENTICATED", data: {
      username: 'TODO' 
    }});
  } else {
    res.send({ error: true, status: "INVALID_SESSION" });
  }
});

export { sessions };
