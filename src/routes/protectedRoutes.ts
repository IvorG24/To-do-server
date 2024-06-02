import express, { Router } from 'express';

import { authenticateToken } from '@/common/middleware/validation';

export const proctectedRoutes: Router = (() => {
  const router = express.Router();
  router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
  });

  return router;
})();
