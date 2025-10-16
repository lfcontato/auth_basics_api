#!/bin/bash
vercel pull --environment=development
vercel env pull .env.development
vercel --prod