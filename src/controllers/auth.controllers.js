import userModel from "../models/user.model.js";
import sessionModel from "../models/session.model.js";
import bcrypt from "bcrypt";
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

  const hashPassword = await bcrypt.hash(password, 10);

  const user = await userModel.create({
    username,
    email,
    password: hashPassword,
  });

  const refreshToken = await jwt.sign(
    {
      id: user._id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );
  const hashRefreshToken = await bcrypt.hash(refreshToken, 10);

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
    process.env.JWT_SECRET,
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

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(201).json({
      message: "Invalid credentials.",
    });
  }

  const refreshToken = await jwt.sign(
    {
      id: user._id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );
  const hashRefreshToken = await bcrypt.hash(refreshToken, 10);

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
    process.env.JWT_SECRET,
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

const rotateToken = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token not found.",
    });
  }

  const decoded = await jwt.verify(refreshToken, process.env.JWT_SECRET);
  const session = await sessionModel.findOne({
    user: decoded.id,
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
    process.env.JWT_SECRET,
    {
      expiresIn: "10m",
    },
  );

  const newRefreshToken = await jwt.sign(
    {
      id: decoded.id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );
  const hashNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
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

  const decoded = await jwt.verify(refreshToken, process.env.JWT_SECRET);
  const session = await sessionModel.findOne({
    user: decoded.id,
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

  const decoded = await jwt.verify(refreshToken, process.env.JWT_SECRET);
  const session = await sessionModel.updateMany(
    {
      user: decoded.id,
      revoked: false,
    },
    {
      revoked: true,
    },
  );

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
