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

const RegisterParams = z.object({
  username: z.string(),
  password: z.string(),
});

app.post("/register", async (req, res) => {
  const params = RegisterParams.parse(req.body);

  // ensure the user exists
  const user = await User.findOne({
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

  User.create({
    username: params.username,
    password: hashedPassword,
  });

  res.send({ error: false, status: "SUCCESS" });
});
