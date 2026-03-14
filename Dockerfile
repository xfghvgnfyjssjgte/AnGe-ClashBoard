FROM --platform=linux/amd64 docker.io/guergeiro/pnpm:lts-latest AS builder

WORKDIR /build

COPY . .

RUN pnpm install
RUN pnpm build

FROM docker.io/node:22-alpine

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && corepack pnpm install --prod --frozen-lockfile --ignore-scripts

RUN mkdir -p .tools/mihomo-bin \
  && node -e "const fs=require('node:fs');const path=require('node:path');const https=require('node:https');const zlib=require('node:zlib');const pickAsset=(assets)=>{if(process.arch==='x64'){return assets.find((item)=>/^mihomo-linux-amd64-compatible-v[0-9.]+\\.gz$/i.test(item.name))||assets.find((item)=>/^mihomo-linux-amd64-v[0-9.]+\\.gz$/i.test(item.name));}if(process.arch==='arm64'){return assets.find((item)=>/^mihomo-linux-arm64-v[0-9.]+\\.gz$/i.test(item.name));}throw new Error('Unsupported architecture: '+process.arch);};const requestJson=(url)=>new Promise((resolve,reject)=>{https.get(url,{headers:{'User-Agent':'AnGe-ClashBoard','Accept':'application/vnd.github+json'}},(res)=>{if(res.statusCode!==200){reject(new Error('Failed to fetch release metadata: '+res.statusCode));res.resume();return;}let body='';res.setEncoding('utf8');res.on('data',(chunk)=>body+=chunk);res.on('end',()=>{try{resolve(JSON.parse(body));}catch(error){reject(error);}});}).on('error',reject);});const download=(url)=>new Promise((resolve,reject)=>{https.get(url,{headers:{'User-Agent':'AnGe-ClashBoard'}},(res)=>{if(res.statusCode!==200){reject(new Error('Failed to download mihomo asset: '+res.statusCode));res.resume();return;}resolve(res);}).on('error',reject);});(async()=>{const release=await requestJson('https://api.github.com/repos/MetaCubeX/mihomo/releases/latest');const asset=pickAsset(release.assets||[]);if(!asset){throw new Error('No matching mihomo asset found for '+process.arch);}const res=await download(asset.browser_download_url);const targetPath=path.resolve('.tools/mihomo-bin/mihomo');await new Promise((resolve,reject)=>{const output=fs.createWriteStream(targetPath,{mode:0o755});res.pipe(zlib.createGunzip()).pipe(output);res.on('error',reject);output.on('finish',resolve);output.on('error',reject);});})();" \
  && chmod +x .tools/mihomo-bin/mihomo

COPY --from=builder /build/dist ./dist
COPY config ./config
COPY server ./server

ENV PORT=2048

EXPOSE 2048

CMD ["node", "server/index.mjs"]
