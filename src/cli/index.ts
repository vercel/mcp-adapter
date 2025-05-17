#!/usr/bin/env node

import { Command } from 'commander';
import fs from 'fs/promises';
import path from 'path';
import chalk from 'chalk';

const program = new Command();

const ROUTE_TEMPLATE = `import { createMcpHandler } from '@vercel/mcp-adapter';
import { z } from 'zod';

const handler = createMcpHandler(
  server => {
    server.tool(
      'roll_dice',
      'Rolls an N-sided die',
      { 
        sides: z.number().int().min(2)
      },
      async ({ sides }) => {
        const value = 1 + Math.floor(Math.random() * sides);
        return {
          content: [{ type: 'text', text: \`🎲 You rolled a \${value}!\` }],
        };
      }
    );
  },
  {
    // Optional server options
  },
  {
    // Optional redis config
    redisUrl: process.env.REDIS_URL,
    // You need these endpoints
    basePath: '/api',
    maxDuration: 60,
    verboseLogs: true,
  }
);

export { handler as GET, handler as POST };
`;

async function detectPackageManager(): Promise<'npm' | 'pnpm' | 'yarn' | 'bun'> {
  const cwd = process.cwd();
  try {
    // Check for lock files in order of preference
    const files = await fs.readdir(cwd);
    
    if (files.includes('bun.lockb')) return 'bun';
    if (files.includes('pnpm-lock.yaml')) return 'pnpm';
    if (files.includes('yarn.lock')) return 'yarn';
    if (files.includes('package-lock.json')) return 'npm';
    
    // Fallback to npm if no lock file found
    return 'npm';
  } catch (error) {
    return 'npm';
  }
}

async function installDependencies(packageManager: 'npm' | 'pnpm' | 'yarn' | 'bun') {
  const execSync = (await import('child_process')).execSync;
  const dependencies = ['@vercel/mcp-adapter', 'zod'];
  
  const commands = {
    npm: `npm install ${dependencies.join(' ')}`,
    pnpm: `pnpm add ${dependencies.join(' ')}`,
    yarn: `yarn add ${dependencies.join(' ')}`,
    bun: `bun add ${dependencies.join(' ')}`
  };

  try {
    console.log(chalk.blue(`\nInstalling dependencies using ${packageManager}...`));
    execSync(commands[packageManager], { stdio: 'inherit' });
    console.log(chalk.green('\n✅ Dependencies installed successfully!'));
  } catch (error) {
    console.error(chalk.red('\n❌ Failed to install dependencies. You can install them manually:'));
    console.log(chalk.yellow(`\n${commands[packageManager]}`));
  }
}

async function init() {
  try {
    // Check if we're in a Next.js project
    const packageJson = JSON.parse(
      await fs.readFile(path.join(process.cwd(), 'package.json'), 'utf-8')
    );
    
    if (!packageJson.dependencies?.next && !packageJson.devDependencies?.next) {
      console.error(chalk.red('❌ This command must be run in a Next.js project'));
      process.exit(1);
    }

    // Create the app/api/[transport] directory structure
    const routePath = path.join(process.cwd(), 'app', 'api', '[transport]');
    await fs.mkdir(routePath, { recursive: true });

    // Create the route.ts file
    const routeFilePath = path.join(routePath, 'route.ts');
    await fs.writeFile(routeFilePath, ROUTE_TEMPLATE);

    console.log(chalk.green('✅ Successfully created MCP route handler!'));
    
    // Detect and use the appropriate package manager
    const packageManager = await detectPackageManager();
    await installDependencies(packageManager);

  } catch (error) {
    console.error(chalk.red('Error creating MCP route handler:'), error);
    process.exit(1);
  }
}

program
  .name('@vercel/mcp-adapter')
  .description('Initialize MCP route handler in your Next.js project')
  .action(init);

program.parse(); 