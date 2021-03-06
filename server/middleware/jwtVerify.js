require("dotenv").config();
const jwt = require("jsonwebtoken");

module.exports = async (req, res, next) => {
  try {
    const auth = req.header("token");
    if (!auth) {
      return res.status(403).json({ msg: "Not Authorized" });
    } else {
      const data = jwt.verify(auth, "Some secret");
      req.user = data.email;
      return next();
    }
  } catch (error) {
    return res.status(403).json({ msg: "Not Authorized" });
  }
  next();
};
