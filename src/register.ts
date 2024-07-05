import {
  Model,
  InferAttributes,
  InferCreationAttributes,
  DataTypes,
} from "sequelize";
import { z } from "zod";
import { sequelize, app } from "./index";
import bcrypt from "bcrypt";
import crypto from "crypto";
import User from "./User";
import { createSession } from "./utils";

const RegisterParams = z.object({
  username: z.string(),
  password: z.string(),
});

app.post("/register", async (req, res) => {
  const parseResult = RegisterParams.safeParse(req.body);
  if (!parseResult.success) {
    res.send({ error: true, status: "INVALID_USERNAME_OR_PASSWORD" });
    return;
  }
  const params = parseResult.data;

  // ensure the user exists
  let user = await User.findOne({
    where: {
      username: params.username,
    },
  });
  if (user) {
    res.send({ error: true, status: "USER_ALREADY_EXISTS" });
    return;
  }

  // hash given password
  const hashedPassword = await bcrypt.hash(params.password, 10);

  user = await User.create({
    username: params.username,
    password: hashedPassword,
  });
  res.send({ error: false, status: "USER_REGISTERED", data: createSession(user.username) });
});
