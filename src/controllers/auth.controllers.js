import userModel from "../models/user.model.js";
import sessionModel from "../models/session.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const register = async (req, res) => {
  const { username, email, password } = req.body;

  const UserAlreadyExists = await userModel.findOne({
    $or: [{ username }, { email }],
  });
  if (UserAlreadyExists) {
    return res.status(409).json({
      message: "User already exists.",
    });
  }

  const hashPassword = await crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const user = await userModel.create({
    username,
    email,
    password: hashPassword,
  });

  const refreshToken = await jwt.sign(
    {
      id: user._id,
    },
    process.env.REFRESH_JWT_TOKEN,
    {
      expiresIn: "7d",
    },
  );
  const hashRefreshToken = await crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await sessionModel.create({
    user,
    refreshToken: hashRefreshToken,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = await jwt.sign(
    {
      id: user._id,
      sessionId: session._id,
    },
    process.env.ACCESS_JWT_TOKEN,
    {
      expiresIn: "10m",
    },
  );

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.status(201).json({
    message: "User created successfully.",
    user: {
      username: user.username,
      email: user.email,
    },
    token: accessToken,
  });
};

const login = async (req, res) => {
  const { username, email, password } = req.body;

  const user = await userModel.findOne({
    $or: [{ username }, { email }],
  });
  if (!user) {
    return res.status(401).json({
      message: "Invalid credentials.",
    });
  }

  const hashPassword = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
  const bufferA = Buffer.from(hashPassword, "hex");
  const bufferB = Buffer.from(user.password, "hex");
  if (bufferA.length !== bufferB.length) {
    return res.status(401).json({
      message: "Invalid credentials.",
    });
  }
  const isPasswordValid = crypto.timingSafeEqual(bufferA, bufferB);
  if (!isPasswordValid) {
    return res.status(401).json({
      message: "Invalid credentials.",
    });
  }

  const refreshToken = await jwt.sign(
    {
      id: user._id,
    },
    process.env.REFRESH_JWT_TOKEN,
    {
      expiresIn: "7d",
    },
  );
  const hashRefreshToken = await crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await sessionModel.create({
    user,
    refreshToken: hashRefreshToken,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = await jwt.sign(
    {
      id: user._id,
      sessionId: session._id,
    },
    process.env.ACCESS_JWT_TOKEN,
    {
      expiresIn: "10m",
    },
  );

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.status(201).json({
    message: "Logged in successfully.",
    user: {
      username: user.username,
      email: user.email,
    },
    token: accessToken,
  });
};

const rotateToken = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token not found.",
    });
  }

  const decoded = await jwt.verify(refreshToken, process.env.REFRESH_JWT_TOKEN);
  const session = await sessionModel.findOne({
    refreshToken: crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex"),
    revoked: false,
  });
  if (!session) {
    return res.status(401).json({
      message: "Invalid Referesh token.",
    });
  }

  const accessToken = await jwt.sign(
    {
      id: decoded.id,
    },
    process.env.ACCESS_JWT_TOKEN,
    {
      expiresIn: "10m",
    },
  );

  const newRefreshToken = await jwt.sign(
    {
      id: decoded.id,
    },
    process.env.REFRESH_JWT_TOKEN,
    {
      expiresIn: "7d",
    },
  );
  const hashNewRefreshToken = await crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");
  session.refreshToken = hashNewRefreshToken;
  await session.save();

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.status(200).json({
    message: "Access Token refreshed successfully!",
    token: accessToken,
  });
};

const logout = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token not found.",
    });
  }

  const decoded = await jwt.verify(
    refreshToken,
    process.env.REFRESH_JWT_SECRET,
  );
  const session = await sessionModel.findOne({
    refreshToken: crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex"),
    revoked: false,
  });
  if (!session) {
    return res.status(401).json({
      message: "Invalid Referesh token.",
    });
  }

  session.revoked = true;
  await session.save();

  res.clearCookie("refreshToken");
  res.status(200).json({
    message: "Logged out successfully",
  });
};

const logoutall = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token not found.",
    });
  }

  const decoded = await jwt.verify(
    refreshToken,
    process.env.REFRESH_JWT_SECRET,
  );
  const session = await sessionModel.updateMany(
    {
      refreshToken: crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex"),
      revoked: false,
    },
    {
      revoked: true,
    },
  );
  if (!session) {
    return res.status(401).json({
      message: "Invalid refresh token.",
    });
  }

  res.clearCookie("refreshToken");
  res.status(200).json({
    message: "Logged out from all devices successfully",
  });
};

const authControllers = {
  register,
  login,
  rotateToken,
  logout,
  logoutall,
};

export default authControllers;
