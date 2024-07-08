import { z } from "zod";
import { app } from "./index";
import bcrypt from "bcrypt";
import crypto from "crypto";
import User from "./User";
import { createSession } from "./utils";

const sessions = new Map<string, Set<string>>();

const LoginParams = z.object({
  username: z.string(),
  password: z.string(),
});

app.post("/login", async (req, res) => {
  const parseResult = LoginParams.safeParse(req.body);
  if (!parseResult.success) {
    res.send({ error: true, status: "INVALID_USERNAME_OR_PASSWORD" });
    return;
  }
  const params = parseResult.data;

  // ensure the user exists
  const user = await User.findOne({
    where: {
      username: params.username,
    },
  });
  if (!user) {
    res.send({ error: true, status: "INVALID_USERNAME_OR_PASSWORD" });
    return;
  }

  // ensure the password is correct
  const correct = await bcrypt.compare(params.password, user.password);

  if (correct) {
    // create a session
    res.send({
      error: false,
      status: "SUCCESSFUL_AUTHENTICATION",
      data: createSession(user.id),
    });
  } else {
    res.send({ error: true, status: "INVALID_USERNAME_OR_PASSWORD" });
  }
});

export { sessions };
