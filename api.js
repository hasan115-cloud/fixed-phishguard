import serverless from 'serverless-http';
import app from '../../server.js';
import { initDatabase } from '../../server/db.js';

let dbInitialized = false;

const serverlessHandler = serverless(app, {
  binary: [
    'application/zip',
    'application/octet-stream',
    'application/pdf',
    'image/*'
  ],
  request: (request, event) => {
    const clientIp = event.headers['x-forwarded-for']?.split(',')[0].trim() ||
                     event.headers['client-ip'] ||
                     event.requestContext?.identity?.sourceIp;
    if (clientIp) {
      request.headers['x-forwarded-for'] = clientIp;
    }
  }
});

export const handler = async (event, context) => {
  if (!dbInitialized) {
    try {
      await initDatabase();
      dbInitialized = true;
    } catch (e) {
      console.warn('[Netlify Function] DB init note:', e.message);
    }
  }

  if (event.path && event.path.startsWith('/.netlify/functions/api')) {
    event.path = event.path.replace(/^\/\.netlify\/functions\/api/, '');
    if (!event.path.startsWith('/api') && event.path !== '/') {
      event.path = '/api' + event.path;
    }
  }

  return await serverlessHandler(event, context);
};
