const express = require("express");
const bodyParser = require("body-parser");
const swaggerUi = require("swagger-ui-express");
const swaggerJsDoc = require("swagger-jsdoc");
const { PrismaClient } = require("@prisma/client");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");

const prisma = new PrismaClient();
const app = express();
app.use(bodyParser.json());

const SECRET_KEY = "your_secret_key"; // Troque por um segredo forte e seguro

// Consfiguração do Swagger
const swaggerOptions = {
  swaggerDefinition: {
    openapi: "3.0.0",
    info: {
      title: "User API",
      version: "2.0.0",
      description: "API for user management with authentication",
    },
    servers: [{ url: "http://localhost:3000" }],
  },
  apis: ["./index.js"],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Middleware para autenticação
function authenticateToken(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).send({ error: "Access denied" });

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send({ error: "Invalid token" });
  }
}

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - name
 *               - email
 *               - password
 *     responses:
 *       201:
 *         description: User registered successfully
 */
app.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email is required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const user = await prisma.user.create({
        data: { name, email, password: hashedPassword },
      });
      res.status(201).json(user);
    } catch (err) {
      res.status(400).json({ error: "Email already exists" });
    }
  }
);

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login a user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - email
 *               - password
 *     responses:
 *       200:
 *         description: Login successful
 */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).send({ error: "User not found" });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send({ error: "Invalid password" });

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Retrieve a list of users with pagination
 *     tags: [User]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: The page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *         description: The number of users per page
 *       - in: query
 *         name: name
 *         schema:
 *           type: string
 *         description: Filter by name
 *     responses:
 *       200:
 *         description: A list of users
 */
app.get("/users", authenticateToken, async (req, res) => {
  const { page = 1, limit = 10, name } = req.query;

  const filters = {};
  if (name) filters.name = { contains: name, mode: "insensitive" };

  const users = await prisma.user.findMany({
    where: filters,
    skip: (page - 1) * limit,
    take: parseInt(limit),
  });

  res.json(users);
});

/**
 * @swagger
 * /users/{id}:
 *   delete:
 *     summary: Delete a user by ID
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: The user ID
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       404:
 *         description: User not found
 */
app.delete("/users/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
  
    try {
      const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
  
      await prisma.user.delete({ where: { id: parseInt(id) } });
      res.status(200).json({ message: "User deleted successfully" });
    } catch (err) {
      res.status(500).json({ error: "An error occurred while deleting the user" });
    }
  });
  

// Start the server
app.listen(3000, () => {
  console.log("Servidor rodando na porta http://localhost:3000");
  console.log("Swagger docs are available at http://localhost:3000/api-docs");
});
