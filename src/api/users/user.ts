import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import express, { Request, Response, Router } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

const prisma = new PrismaClient();
const router = express.Router();
const JWT_SECRET: any = process.env.JWT_SECRET_KEY;

export const userRouter: Router = (() => {
  const LoginSchema = z.object({
    email: z.string().email(),
    password: z.string(),
  });

  const RegistrationSchema = z.object({
    email: z.string().email(),
    password: z.string(),
  });

  router.post('/login', async (req: Request, res: Response) => {
    const { email, password } = LoginSchema.parse(req.body);
    try {
      // Validate email and password presence (optional)
      if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
      }
      // Fetch user from Prisma by email
      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return res.status(401).json({ message: 'Invalid email, try again' });
      }
      // Compare provided password with stored hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password, try again' });
      }
      const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: '1h', // Token validity duration
      });

      res.json({ message: 'Sign-in successful!', token });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ message: 'An error occurred during sign-in.' });
    }
  });

  router.post('/register', async (req: Request, res: Response) => {
    try {
      const { email, password } = RegistrationSchema.parse(req.body);

      // Hash the password before saving it
      const hashedPassword = await bcrypt.hash(password, 10);

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists.' });
      }

      await prisma.user.create({
        data: { email, password: hashedPassword },
      });

      return res.status(200).json({ message: 'User registered successfully' });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: 'Invalid request' });
      } else {
        console.error('Error registering user:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
      }
    }
  });

  return router;
})();
