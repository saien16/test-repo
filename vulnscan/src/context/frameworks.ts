/**
 * フレームワーク推定。
 *
 * 依存名を主根拠とし、規約ファイル（next.config.js, manage.py など）と
 * 標準ライブラリの import を補助的に使う。
 */

import type { Dependency, FrameworkInfo } from '../types/context.js';
import type { AnalyzableSource } from './symbols.js';

/** 依存名の完全一致による対応表 */
const EXACT: Record<string, Record<string, string>> = {
  npm: {
    express: 'Express',
    next: 'Next.js',
    nuxt: 'Nuxt',
    koa: 'Koa',
    fastify: 'Fastify',
    hapi: 'hapi',
    '@hapi/hapi': 'hapi',
    '@nestjs/core': 'NestJS',
    react: 'React',
    'react-dom': 'React',
    vue: 'Vue',
    svelte: 'Svelte',
    '@angular/core': 'Angular',
    'socket.io': 'Socket.IO',
    sequelize: 'Sequelize',
    typeorm: 'TypeORM',
    '@prisma/client': 'Prisma',
    prisma: 'Prisma',
    mongoose: 'Mongoose',
    knex: 'Knex',
    'apollo-server': 'Apollo Server',
    graphql: 'GraphQL',
    passport: 'Passport',
    jsonwebtoken: 'JWT (jsonwebtoken)',
    electron: 'Electron',
    'aws-lambda': 'AWS Lambda',
    'serverless-http': 'AWS Lambda',
    handlebars: 'Handlebars',
    ejs: 'EJS',
    pug: 'Pug',
  },
  PyPI: {
    django: 'Django',
    flask: 'Flask',
    fastapi: 'FastAPI',
    starlette: 'Starlette',
    tornado: 'Tornado',
    pyramid: 'Pyramid',
    bottle: 'Bottle',
    sanic: 'Sanic',
    aiohttp: 'aiohttp',
    sqlalchemy: 'SQLAlchemy',
    celery: 'Celery',
    jinja2: 'Jinja2',
    'djangorestframework': 'Django REST Framework',
    pyramid_jinja2: 'Pyramid',
    boto3: 'AWS SDK (boto3)',
  },
  Go: {
    'github.com/gin-gonic/gin': 'Gin',
    'github.com/labstack/echo': 'Echo',
    'github.com/labstack/echo/v4': 'Echo',
    'github.com/gofiber/fiber': 'Fiber',
    'github.com/gofiber/fiber/v2': 'Fiber',
    'github.com/gorilla/mux': 'Gorilla Mux',
    'github.com/go-chi/chi': 'chi',
    'github.com/go-chi/chi/v5': 'chi',
    'gorm.io/gorm': 'GORM',
    'github.com/spf13/cobra': 'Cobra',
    'google.golang.org/grpc': 'gRPC',
  },
  RubyGems: {
    rails: 'Ruby on Rails',
    sinatra: 'Sinatra',
    rack: 'Rack',
    sequel: 'Sequel',
    hanami: 'Hanami',
  },
  Packagist: {
    'laravel/framework': 'Laravel',
    'slim/slim': 'Slim',
    'cakephp/cakephp': 'CakePHP',
    'yiisoft/yii2': 'Yii2',
    'drupal/core': 'Drupal',
  },
};

/** 依存名の前方一致による対応表 */
const PREFIX: Array<{ ecosystem: string; prefix: string; framework: string }> = [
  { ecosystem: 'npm', prefix: '@nestjs/', framework: 'NestJS' },
  { ecosystem: 'npm', prefix: '@angular/', framework: 'Angular' },
  { ecosystem: 'npm', prefix: '@apollo/', framework: 'Apollo' },
  { ecosystem: 'Maven', prefix: 'org.springframework.boot:', framework: 'Spring Boot' },
  { ecosystem: 'Maven', prefix: 'org.springframework:', framework: 'Spring' },
  { ecosystem: 'Maven', prefix: 'org.hibernate:', framework: 'Hibernate' },
  { ecosystem: 'Maven', prefix: 'org.apache.struts:', framework: 'Struts' },
  { ecosystem: 'Maven', prefix: 'jakarta.servlet:', framework: 'Servlet API' },
  { ecosystem: 'Maven', prefix: 'javax.servlet:', framework: 'Servlet API' },
  { ecosystem: 'Packagist', prefix: 'symfony/', framework: 'Symfony' },
  { ecosystem: 'PyPI', prefix: 'django-', framework: 'Django' },
];

/** 規約ファイルによる検出 */
const MARKER_FILES: Array<{ pattern: RegExp; framework: string }> = [
  { pattern: /(?:^|\/)next\.config\.(?:js|mjs|ts|cjs)$/, framework: 'Next.js' },
  { pattern: /(?:^|\/)nuxt\.config\.(?:js|ts)$/, framework: 'Nuxt' },
  { pattern: /(?:^|\/)angular\.json$/, framework: 'Angular' },
  { pattern: /(?:^|\/)svelte\.config\.js$/, framework: 'Svelte' },
  { pattern: /(?:^|\/)manage\.py$/, framework: 'Django' },
  { pattern: /(?:^|\/)wsgi\.py$/, framework: 'WSGI アプリケーション' },
  { pattern: /(?:^|\/)asgi\.py$/, framework: 'ASGI アプリケーション' },
  { pattern: /(?:^|\/)artisan$/, framework: 'Laravel' },
  { pattern: /(?:^|\/)config\/routes\.rb$/, framework: 'Ruby on Rails' },
  { pattern: /(?:^|\/)serverless\.ya?ml$/, framework: 'Serverless Framework' },
  { pattern: /(?:^|\/)Dockerfile$/, framework: 'Docker' },
  { pattern: /(?:^|\/)docker-compose\.ya?ml$/, framework: 'Docker Compose' },
  { pattern: /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/, framework: 'GitHub Actions' },
  { pattern: /(?:^|\/)(?:pages\/api|app)\/.*route\.[jt]sx?$/, framework: 'Next.js' },
];

/** ソース中の import から検出する（標準ライブラリなど依存宣言に現れないもの） */
const IMPORT_MARKERS: Array<{ language: string; pattern: RegExp; framework: string }> = [
  { language: 'go', pattern: /"net\/http"/, framework: 'net/http (Go 標準)' },
  { language: 'java', pattern: /import\s+javax?\.servlet/, framework: 'Servlet API' },
  { language: 'python', pattern: /^\s*from\s+flask\s+import|^\s*import\s+flask\b/m, framework: 'Flask' },
  { language: 'python', pattern: /^\s*from\s+django|^\s*import\s+django\b/m, framework: 'Django' },
  { language: 'php', pattern: /use\s+Illuminate\\/, framework: 'Laravel' },
];

/**
 * フレームワークを推定する。
 * 同じフレームワークが複数根拠で見つかった場合は最初の根拠を採用する。
 */
export function detectFrameworks(
  dependencies: readonly Dependency[],
  allPaths: readonly string[],
  sources: readonly AnalyzableSource[],
): FrameworkInfo[] {
  const found = new Map<string, FrameworkInfo>();

  const add = (name: string, evidence: string, version?: string): void => {
    const existing = found.get(name);
    if (existing) {
      // バージョンが後から判ったら補完する
      if (!existing.version && version) existing.version = version;
      return;
    }
    found.set(name, { name, evidence, version });
  };

  for (const dep of dependencies) {
    const exact = EXACT[dep.ecosystem]?.[dep.name.toLowerCase()] ?? EXACT[dep.ecosystem]?.[dep.name];
    if (exact) {
      add(exact, `${dep.manifest} の依存 ${dep.name}`, dep.version);
      continue;
    }
    for (const rule of PREFIX) {
      if (rule.ecosystem === dep.ecosystem && dep.name.startsWith(rule.prefix)) {
        add(rule.framework, `${dep.manifest} の依存 ${dep.name}`, dep.version);
        break;
      }
    }
  }

  for (const path of allPaths) {
    for (const marker of MARKER_FILES) {
      if (marker.pattern.test(path)) add(marker.framework, `設定ファイル ${path}`);
    }
  }

  for (const source of sources) {
    for (const marker of IMPORT_MARKERS) {
      if (marker.language !== source.language) continue;
      if (found.has(marker.framework)) continue;
      const head = source.masked.noComment.slice(0, 60).join('\n');
      if (marker.pattern.test(head)) add(marker.framework, `${source.path} の import`);
    }
  }

  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}
