require('dotenv').config();
const axios = require('axios');
const ethers = require('ethers');
const crypto = require('crypto');
const fs = require('fs');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const userAgents = require('user-agents');
const readline = require('readline');
const chalk = require('chalk'); // If using chalk v5, use require('chalk').default

// Adjustable settings (can be changed via interactive menu)
let DELAY_BETWEEN_WALLETS = 2000; // Delay between wallet operations (ms)
let MAX_RETRIES = 3;              // Maximum number of login retries
let CHECK_INTERVAL = 60 * 1000;   // Status check interval (ms)

// File for storing reward claim times
const CLAIMS_FILE = './claims.json';
let claims = {};
if (fs.existsSync(CLAIMS_FILE)) {
  try {
    claims = JSON.parse(fs.readFileSync(CLAIMS_FILE, 'utf8'));
  } catch (error) {
    console.error('Error loading claims.json:', error.message);
  }
}
function saveClaims() {
  try {
    fs.writeFileSync(CLAIMS_FILE, JSON.stringify(claims, null, 2));
  } catch (error) {
    console.error('Error saving claims.json:', error.message);
  }
}

// Load private keys from .env
let privateKeys = [];
if (process.env.PRIVATE_KEY) {
  if (process.env.PRIVATE_KEY.includes(',')) {
    privateKeys = process.env.PRIVATE_KEY.split(',').map(key => key.trim());
  } else {
    privateKeys.push(process.env.PRIVATE_KEY);
  }
}
let keyIndex = 1;
while (process.env[`PRIVATE_KEY_${keyIndex}`]) {
  privateKeys.push(process.env[`PRIVATE_KEY_${keyIndex}`]);
  keyIndex++;
}
if (privateKeys.length === 0) {
  console.error('\x1b[31m%s\x1b[0m', '❌ Error: No private keys found in .env');
  process.exit(1);
}
console.log(`\n📋 Loaded ${privateKeys.length} private keys from .env`);

// Load proxies from proxies.txt (if available)
let proxies = [];
try {
  if (fs.existsSync('./proxies.txt')) {
    const proxiesContent = fs.readFileSync('./proxies.txt', 'utf8');
    proxies = proxiesContent
      .split('\n')
      .map(proxy => proxy.trim())
      .filter(proxy => proxy && !proxy.startsWith('#'));
    console.log(`🌐 Loaded ${proxies.length} proxies from proxies.txt`);
  }
} catch (error) {
  console.error('\x1b[33m%s\x1b[0m', `⚠️ Error loading proxies.txt: ${error.message}`);
}

// Function to create proxy agent
function createProxyAgent(proxyString) {
  if (!proxyString) return null;
  try {
    if (proxyString.startsWith('socks://') || proxyString.startsWith('socks4://') || proxyString.startsWith('socks5://')) {
      return new SocksProxyAgent(proxyString);
    }
    let formattedProxy = proxyString;
    if (!formattedProxy.includes('://')) {
      if (formattedProxy.includes('@') || !formattedProxy.match(/^\d+\.\d+\.\d+\.\d+:\d+$/)) {
        formattedProxy = `http://${formattedProxy}`;
      } else {
        const [host, port] = formattedProxy.split(':');
        formattedProxy = `http://${host}:${port}`;
      }
    }
    return new HttpsProxyAgent(formattedProxy);
  } catch (error) {
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Error creating proxy agent for ${proxyString}: ${error.message}`);
    return null;
  }
}

// Function to get random user-agent
function getRandomUserAgent() {
  const ua = new userAgents({ deviceCategory: 'desktop' });
  return ua.toString();
}

// ASCII banner
function printBanner() {
  process.stdout.write('\x1B[2J\x1B[0f'); // Clear screen
  console.log(chalk.yellow(`
       █████╗ ██████╗ ██████╗     ███╗   ██╗ ██████╗ ██████╗ ███████╗
      ██╔══██╗██╔══██╗██╔══██╗    ████╗  ██║██╔═══██╗██╔══██╗██╔════╝
      ███████║██║  ██║██████╔╝    ██╔██╗ ██║██║   ██║██║  ██║█████╗  
      ██╔══██║██║  ██║██╔══██╗    ██║╚██╗██║██║   ██║██║  ██║██╔══╝  
      ██║  ██║██████╔╝██████╔╝    ██║ ╚████║╚██████╔╝██████╔╝███████╗
      ╚═╝  ╚═╝╚═════╝ ╚═════╝     ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝   

      SyntheliX Manager Bot — Automation Script  
  `));
}

// Function to start node for a wallet
async function startSynthelixNodeForWallet(privateKey, proxyString, walletLabel, retryCount = 0) {
  const wallet = new ethers.Wallet(privateKey);
  const address = wallet.address;
  const proxyAgent = proxyString ? createProxyAgent(proxyString) : null;
  const userAgent = getRandomUserAgent();

  // Log proxy info if used
  console.log('\x1b[36m%s\x1b[0m', `\n🔄 Starting node for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}${proxyString ? ` (using proxy: ${proxyString})` : ' (no proxy)'}`);

  // Add timeout (e.g., 30 seconds) to axiosConfig
  const axiosConfig = {
    httpsAgent: proxyAgent,
    httpAgent: proxyAgent,
    timeout: 30000
  };

  try {
    let cookies = '';
    let csrfToken = '';
    const commonHeaders = {
      'accept': '*/*',
      'content-type': 'application/json',
      'user-agent': userAgent,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'Referer': 'https://dashboard.synthelix.io/'
    };

    process.stdout.write('\x1b[90mFetching auth providers... \x1b[0m');
    const providersResponse = await axios.get('https://dashboard.synthelix.io/api/auth/providers', {
      ...axiosConfig,
      headers: commonHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    if (providersResponse.headers['set-cookie']) {
      cookies = providersResponse.headers['set-cookie'].join('; ');
    }

    process.stdout.write('\x1b[90mFetching CSRF token... \x1b[0m');
    const csrfResponse = await axios.get('https://dashboard.synthelix.io/api/auth/csrf', {
      ...axiosConfig,
      headers: { ...commonHeaders, 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    csrfToken = csrfResponse.data.csrfToken;
    if (csrfResponse.headers['set-cookie']) {
      cookies = [...(cookies ? [cookies] : []), ...csrfResponse.headers['set-cookie']].join('; ');
    }

    process.stdout.write('\x1b[90mPreparing message signature... \x1b[0m');
    const nonce = generateRandomString(32);
    const requestId = Date.now().toString();
    const issuedAt = new Date().toISOString();
    const domain = { name: "Synthelix", version: "1", chainId: 1, verifyingContract: "0x0000000000000000000000000000000000000000" };
    const types = { Authentication: [{ name: "address", type: "address" }, { name: "statement", type: "string" }, { name: "nonce", type: "string" }, { name: "requestId", type: "string" }, { name: "issuedAt", type: "string" }] };
    const value = { address, statement: "Sign in to enter Synthelix Dashboard.", nonce, requestId, issuedAt };

    let signature;
    try {
      if (typeof wallet.signTypedData === 'function') {
        signature = await wallet.signTypedData(domain, types, value);
      } else if (typeof wallet._signTypedData === 'function') {
        signature = await wallet._signTypedData(domain, types, value);
      } else {
        const messageString = JSON.stringify({ domain, types, value });
        signature = await wallet.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(messageString))));
      }
    } catch (err) {
      const messageToSign = `${address}:${value.statement}:${value.nonce}:${value.requestId}:${value.issuedAt}`;
      signature = await wallet.signMessage(messageToSign);
    }
    console.log('\x1b[32m%s\x1b[0m', '✓');

    process.stdout.write('\x1b[90mAuthenticating with web3... \x1b[0m');
    const authData = new URLSearchParams({
      address, signature, domain: JSON.stringify(domain), types: JSON.stringify(types), value: JSON.stringify(value),
      redirect: 'false', callbackUrl: '/', csrfToken, json: 'true'
    });
    const authResponse = await axios.post('https://dashboard.synthelix.io/api/auth/callback/web3', authData.toString(), {
      ...axiosConfig,
      headers: { ...commonHeaders, 'content-type': 'application/x-www-form-urlencoded', 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    if (authResponse.headers['set-cookie']) {
      cookies = [...(cookies ? [cookies] : []), ...authResponse.headers['set-cookie']].join('; ');
    }

    process.stdout.write('\x1b[90mFetching session... \x1b[0m');
    const sessionResponse = await axios.get('https://dashboard.synthelix.io/api/auth/session', {
      ...axiosConfig,
      headers: { ...commonHeaders, 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    if (sessionResponse.headers['set-cookie']) {
      cookies = [...(cookies ? [cookies] : []), ...sessionResponse.headers['set-cookie']].join('; ');
    }

    const pointsInfo = await getPointsInfo(cookies, commonHeaders, axiosConfig);
    console.log('\x1b[36m%s\x1b[0m', `💎 Points before start: ${pointsInfo.totalPoints || 0}`);

    const statusInfo = await getNodeStatus(cookies, commonHeaders, axiosConfig);
    if (statusInfo.nodeRunning) {
      process.stdout.write('\x1b[90mStopping previously running node... \x1b[0m');
      try {
        const timeRunningHours = statusInfo.currentEarnedPoints / statusInfo.pointsPerHour;
        await axios.post('https://dashboard.synthelix.io/api/node/stop', {
          claimedHours: timeRunningHours,
          pointsEarned: statusInfo.currentEarnedPoints
        }, { ...axiosConfig, headers: { ...commonHeaders, 'Cookie': cookies } });
        console.log('\x1b[32m%s\x1b[0m', '✓');
        console.log('\x1b[32m%s\x1b[0m', `💰 Claimed ${statusInfo.currentEarnedPoints} points`);
        await delay(1000);
      } catch (error) {
        console.log('\x1b[31m%s\x1b[0m', '❌');
        console.error('\x1b[33m%s\x1b[0m', `⚠️ Error stopping node: ${error.message}`);
      }
    }

    process.stdout.write('\x1b[90mStarting node... \x1b[0m');
    await axios.post('https://dashboard.synthelix.io/api/node/start', null, {
      ...axiosConfig,
      headers: { ...commonHeaders, 'Cookie': cookies }
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    console.log('\x1b[32m%s\x1b[0m', `✅ Node started successfully for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}!\n`);

    await claimDailyRewards(address, cookies, commonHeaders, axiosConfig, walletLabel);
    const updatedStatusInfo = await getNodeStatus(cookies, commonHeaders, axiosConfig);
    const updatedPointsInfo = await getPointsInfo(cookies, commonHeaders, axiosConfig);

    console.log('\x1b[33m%s\x1b[0m', `\n📊 Node status for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}:`);
    console.log('\x1b[33m%s\x1b[0m', `🔄 Node status: ${updatedStatusInfo.nodeRunning ? 'Running' : 'Stopped'}`);
    console.log('\x1b[33m%s\x1b[0m', `⏱️ Time left: ${formatTime(updatedStatusInfo.timeLeft)}`);
    console.log('\x1b[33m%s\x1b[0m', `💰 Current points: ${updatedStatusInfo.currentEarnedPoints || 0}`);
    console.log('\x1b[33m%s\x1b[0m', `💸 Points per hour: ${updatedStatusInfo.pointsPerHour || 0}`);
    console.log('\x1b[33m%s\x1b[0m', `💎 Total points: ${updatedPointsInfo.totalPoints || 0}`);
    console.log('\x1b[33m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

    return {
      success: true, address, cookies, commonHeaders, axiosConfig,
      timeLeft: updatedStatusInfo.timeLeft, statusInfo: updatedStatusInfo,
      pointsInfo: updatedPointsInfo, walletLabel
    };
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[31m%s\x1b[0m', `❌ Error starting node for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}: ${error.message}`);
    if (retryCount < MAX_RETRIES) {
      console.log('\x1b[33m%s\x1b[0m', `⚠️ Retrying ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)} (Attempt ${retryCount + 1}/${MAX_RETRIES})...`);
      await delay(5000);
      return startSynthelixNodeForWallet(privateKey, proxyString, walletLabel, retryCount + 1);
    }
    return { success: false, address, error: error.message, walletLabel };
  }
}

// Function to claim daily rewards with time check
async function claimDailyRewards(address, cookies, commonHeaders, axiosConfig, walletLabel) {
  const lastClaimTime = claims[address];
  const now = Date.now();
  const ONE_DAY = 24 * 3600 * 1000;

  if (lastClaimTime && (now - lastClaimTime) < ONE_DAY) {
    console.log('\x1b[33m%s\x1b[0m',
      `ℹ️ Daily rewards already claimed for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}. ` +
      `Next claim in ${formatTime(Math.floor((ONE_DAY - (now - lastClaimTime)) / 1000))}.`);
    return false;
  }

  try {
    process.stdout.write('\x1b[90mClaiming daily rewards... \x1b[0m');
    const updatedHeaders = { ...commonHeaders, 'Cookie': cookies, 'Referer': 'https://dashboard.synthelix.io/' };
    await axios.post('https://dashboard.synthelix.io/api/rew/dailypoints', { points: 1000 }, {
      ...axiosConfig,
      headers: updatedHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    console.log('\x1b[32m%s\x1b[0m', `💰 Claimed 1000 daily points for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}`);

    // Update claim time and save
    claims[address] = now;
    saveClaims();
    return true;
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to claim daily rewards: ${error.message}`);
    if (error.response && error.response.data && error.response.data.error === 'Already claimed today') {
      console.log('\x1b[33m%s\x1b[0m',
        `ℹ️ Daily rewards already claimed for ${walletLabel}: ${address.substring(0, 6)}...${address.substring(address.length - 4)}`);
      claims[address] = now;
      saveClaims();
    }
    return false;
  }
}

// Function to get node status
async function getNodeStatus(cookies, commonHeaders, axiosConfig) {
  try {
    process.stdout.write('\x1b[90mFetching node status... \x1b[0m');
    const updatedHeaders = { ...commonHeaders, 'Cookie': cookies, 'Referer': 'https://dashboard.synthelix.io/' };
    const response = await axios.get('https://dashboard.synthelix.io/api/node/status', {
      ...axiosConfig,
      headers: updatedHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    return response.data;
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to fetch node status: ${error.message}`);
    return { nodeRunning: false, timeLeft: 0, currentEarnedPoints: 0, pointsPerHour: 0 };
  }
}

// Function to get points info
async function getPointsInfo(cookies, commonHeaders, axiosConfig) {
  try {
    process.stdout.write('\x1b[90mFetching points info... \x1b[0m');
    const updatedHeaders = {
      ...commonHeaders,
      'accept': '*/*',
      'accept-language': 'en-US,en;q=0.9',
      'sec-ch-ua': '"Brave";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-gpc': '1',
      'Cookie': cookies,
      'Referer': 'https://dashboard.synthelix.io/'
    };
    const response = await axios.get('https://dashboard.synthelix.io/api/get/points', {
      ...axiosConfig,
      headers: updatedHeaders
    });
    console.log('\x1b[32m%s\x1b[0m', '✓');
    return { totalPoints: response.data.points || 0 };
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m', '❌');
    console.error('\x1b[33m%s\x1b[0m', `⚠️ Failed to fetch points info: ${error.message}`);
    return { totalPoints: 0 };
  }
}

// Function to format time
function formatTime(seconds) {
  if (!seconds) return '0s';
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = Math.floor(seconds % 60);
  let result = '';
  if (hours > 0) result += `${hours}h `;
  if (minutes > 0 || hours > 0) result += `${minutes}m `;
  result += `${remainingSeconds}s`;
  return result.trim();
}

// Function to generate random string
function generateRandomString(length) {
  return crypto.randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length)
    .replace(/[^a-zA-Z0-9]/g, '')
    .replace(/(.{1,4})/g, (m) => Math.random() > 0.5 ? m.toUpperCase() : m);
}

// Delay function
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* 
  Function to monitor nodes (single cycle).
  If inLoop === true, it doesn't prompt "Press Enter to return to menu..."
*/
async function monitorNodesOnce(inLoop = false) {
  console.clear();
  printBanner();
  console.log(`🔍 Checking ${privateKeys.length} wallets — ${new Date().toLocaleString()}\n`);

  let activeWallets = 0;
  const walletSessions = {};

  // Initialize sessions for each wallet
  for (let i = 0; i < privateKeys.length; i++) {
    const privateKey = privateKeys[i];
    const walletLabel = `Wallet ${i + 1}`;
    const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;
    const result = await startSynthelixNodeForWallet(privateKey, proxy, walletLabel);
    if (result.success) {
      walletSessions[result.address] = result;
      activeWallets++;
    }
    if (i < privateKeys.length - 1) await delay(DELAY_BETWEEN_WALLETS);
  }

  // Check node status
  for (let i = 0; i < privateKeys.length; i++) {
    const privateKey = privateKeys[i];
    const wallet = new ethers.Wallet(privateKey);
    const address = wallet.address;
    const walletLabel = `Wallet ${i + 1}`;
    const shortAddress = `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
    const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;

    try {
      if (walletSessions[address] && walletSessions[address].cookies) {
        const session = walletSessions[address];
        const statusInfo = await getNodeStatus(session.cookies, session.commonHeaders, session.axiosConfig);
        const pointsInfo = await getPointsInfo(session.cookies, session.commonHeaders, session.axiosConfig);

        console.log('\x1b[36m%s\x1b[0m', `${walletLabel}: ${short Angka${shortAddress}`);
        console.log('\x1b[33m%s\x1b[0m', `Status: ${statusInfo.nodeRunning ? 'Running' : 'Stopped'}`);
        console.log('\x1b[33m%s\x1b[0m', `Time left: ${formatTime(statusInfo.timeLeft)}`);
        console.log('\x1b[33m%s\x1b[0m', `Current points: ${statusInfo.currentEarnedPoints || 0}`);
        console.log('\x1b[33m%s\x1b[0m', `Points per hour: ${statusInfo.pointsPerHour || 0}`);
        console.log('\x1b[33m%s\x1b[0m', `Total points: ${pointsInfo.totalPoints || 0}`);
        console.log('');

        if (!statusInfo.nodeRunning || statusInfo.timeLeft < 600) {
          console.log('\x1b[33m%s\x1b[0m', `⚠️ Node requires restart for ${walletLabel}: ${shortAddress}`);
          if (statusInfo.nodeRunning && statusInfo.currentEarnedPoints > 0) {
            process.stdout.write('\x1b[90mStopping node to claim points... \x1b[0m');
            try {
              const timeRunningHours = statusInfo.currentEarnedPoints / statusInfo.pointsPerHour;
              await axios.post('https://dashboard.synthelix.io/api/node/stop', {
                claimedHours: timeRunningHours,
                pointsEarned: statusInfo.currentEarnedPoints
              }, { ...session.axiosConfig, headers: { ...session.commonHeaders, 'Cookie': session.cookies } });
              console.log('\x1b[32m%s\x1b[0m', '✓');
              console.log('\x1b[32m%s\x1b[0m', `💰 Claimed ${statusInfo.currentEarnedPoints} points`);
              await delay(1000);
            } catch (error) {
              console.log('\x1b[31m%s\x1b[0m', '❌');
              console.error('\x1b[33m%s\x1b[0m', `⚠️ Error stopping node: ${error.message}`);
            }
          }
          process.stdout.write('\x1b[90mStarting node... \x1b[0m');
          await axios.post('https://dashboard.synthelix.io/api/node/start', null, {
            ...session.axiosConfig,
            headers: { ...session.commonHeaders, 'Cookie': session.cookies }
          });
          console.log('\x1b[32m%s\x1b[0m', '✓');
          await claimDailyRewards(address, session.cookies, session.commonHeaders, session.axiosConfig, walletLabel);
          const updatedStatus = await getNodeStatus(session.cookies, session.commonHeaders, session.axiosConfig);
          const updatedPoints = await getPointsInfo(session.cookies, session.commonHeaders, session.axiosConfig);
          walletSessions[address].timeLeft = updatedStatus.timeLeft;
          walletSessions[address].statusInfo = updatedStatus;
          walletSessions[address].pointsInfo = updatedPoints;
        }
      } else {
        console.log('\x1b[33m%s\x1b[0m', `⚠️ Session expired for ${walletLabel}: ${shortAddress}, logging in again...`);
        const result = await startSynthelixNodeForWallet(privateKey, proxy, walletLabel);
        if (result.success) {
          walletSessions[address] = result;
        }
      }
    } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `❌ Error ${walletLabel}: ${shortAddress}: ${error.message}`);
    }
    if (i < privateKeys.length - 1) await delay(DELAY_BETWEEN_WALLETS);
  }

  console.log('\x1b[36m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log('\x1b[36m%s\x1b[0m', `Summary:`);
  console.log(`Total wallets: ${privateKeys.length}`);
  console.log(`Active nodes: ${activeWallets}`);
  const nextCheckTime = new Date(Date.now() + CHECK_INTERVAL);
  console.log(`Next check: ${nextCheckTime.toLocaleString()}`);
  console.log('\x1b[36m%s\x1b[0m', `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

  if (!inLoop) {
    await askQuestion('Press Enter to return to menu...');
  }
}

/* 
  Function for infinite node monitoring.
  Calls monitorNodesOnce(true) in an infinite loop.
*/
async function monitorNodesInfinite() {
  while (true) {
    await monitorNodesOnce(true);
    await delay(CHECK_INTERVAL);
  }
}

/* ---------------------- Interactive Menu ---------------------- */
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
function askQuestion(query) {
  return new Promise(resolve => rl.question(query, ans => resolve(ans.trim())));
}
async function addPrivateKey() {
  const newKey = await askQuestion('Enter new private key: ');
  if (newKey) {
    privateKeys.push(newKey);
    console.log('✅ Private key added successfully!');
  } else {
    console.log('⚠️ No private key was entered.');
  }
}
async function addProxy() {
  const newProxy = await askQuestion('Enter new proxy (format: host:port or with scheme): ');
  if (newProxy) {
    proxies.push(newProxy);
    console.log('✅ Proxy added successfully!');
  } else {
    console.log('⚠️ No proxy was entered.');
  }
}
function showInfo() {
  console.log('\n📋 Current settings:');
  console.log(`Private keys: ${privateKeys.length}`);
  console.log(`Proxies: ${proxies.length}`);
  if (privateKeys.length > 0) {
    console.log('List of private keys (first 6 and last 4 characters):');
    privateKeys.forEach((key, idx) => {
      console.log(`  [${idx + 1}] ${key.substring(0, 6)}...${key.substring(key.length - 4)}`);
    });
  }
  if (proxies.length > 0) {
    console.log('List of proxies:');
    proxies.forEach((p, idx) => console.log(`  [${idx + 1}] ${p}`));
  }
  console.log('');
}

async function editConstants() {
  console.log('\n📋 Current delay settings:');
  console.log(`1. DELAY_BETWEEN_WALLETS: ${DELAY_BETWEEN_WALLETS} ms`);
  console.log(`2. MAX_RETRIES: ${MAX_RETRIES}`);
  console.log(`3. CHECK_INTERVAL: ${CHECK_INTERVAL} ms`);
  console.log("Enter new value or leave blank to keep current value.");

  let input = await askQuestion("New value for DELAY_BETWEEN_WALLETS (or 'r' for random, range 1000-5000): ");
  if (input.trim().toLowerCase() === 'r') {
    DELAY_BETWEEN_WALLETS = Math.floor(Math.random() * (5000 - 1000 + 1)) + 1000;
    console.log("Random value set: " + DELAY_BETWEEN_WALLETS);
  } else if (input.trim()) {
    let newVal = parseInt(input);
    if (!isNaN(newVal)) DELAY_BETWEEN_WALLETS = newVal;
  }

  input = await askQuestion("New value for MAX_RETRIES (or 'r' for random, range 1-5): ");
  if (input.trim().toLowerCase() === 'r') {
    MAX_RETRIES = Math.floor(Math.random() * (5 - 1 + 1)) + 1;
    console.log("Random value set: " + MAX_RETRIES);
  } else if (input.trim()) {
    let newVal = parseInt(input);
    if (!isNaN(newVal)) MAX_RETRIES = newVal;
  }

  input = await askQuestion("New value for CHECK_INTERVAL (ms) (or 'r' for random, range 30000-120000): ");
  if (input.trim().toLowerCase() === 'r') {
    CHECK_INTERVAL = Math.floor(Math.random() * (120000 - 30000 + 1)) + 30000;
    console.log("Random value set: " + CHECK_INTERVAL);
  } else if (input.trim()) {
    let newVal = parseInt(input);
    if (!isNaN(newVal)) CHECK_INTERVAL = newVal;
  }

  console.log("\nNew settings:");
  console.log(`DELAY_BETWEEN_WALLETS: ${DELAY_BETWEEN_WALLETS} ms`);
  console.log(`MAX_RETRIES: ${MAX_RETRIES}`);
  console.log(`CHECK_INTERVAL: ${CHECK_INTERVAL} ms`);
  await askQuestion('Press Enter to return to menu...');
}

async function mainMenu() {
  while (true) {
    printBanner();
    console.log('Select an action:');
    console.log('1. Run node auto-maintenance (one check cycle)');
    console.log('2. Run node auto-maintenance (infinite loop)');
    console.log('3. Add new private key');
    console.log('4. Add new proxy server');
    console.log('5. Show settings info');
    console.log('6. Edit delay settings');
    console.log('7. Exit');
    const answer = await askQuestion('\nEnter action number: ');
    switch (answer) {
      case '1':
        console.log('🔄 Starting node auto-maintenance. Running one check cycle...\n');
        await monitorNodesOnce();
        break;
      case '2':
        console.log('🔄 Starting node auto-maintenance (infinite loop). Press Ctrl+C to stop.\n');
        await monitorNodesInfinite();
        break;
      case '3':
        await addPrivateKey();
        await askQuestion('Press Enter to return to menu...');
        break;
      case '4':
        await addProxy();
        await askQuestion('Press Enter to return to menu...');
        break;
      case '5':
        showInfo();
        await askQuestion('Press Enter to return to menu...');
        break;
      case '6':
        await editConstants();
        break;
      case '7':
        console.log('Exiting program. Goodbye!');
        rl.close();
        process.exit(0);
      default:
        console.log('⚠️ Invalid choice, please try again.');
        await askQuestion('Press Enter to return to menu...');
    }
  }
}

mainMenu();
