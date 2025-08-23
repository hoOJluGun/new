const crypto = require('crypto');

function verifyTelegramAuth(data, botToken){
  if(!data || !data.hash) return false;
  const { hash, ...rest } = data;
  const sorted = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('\n');
  const secret = crypto.createHash('sha256').update(botToken).digest();
  const hex = crypto.createHmac('sha256', secret).update(sorted).digest('hex');
  return hex === hash;
}

const makeCookie = (name, value, maxAgeSec) => {
  const attrs = [`${name}=${value}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax'];
  if(maxAgeSec) attrs.push(`Max-Age=${maxAgeSec}`);
  return attrs.join('; ');
};

exports.handler = async (event) => {
  try{
    const params = event.queryStringParameters || {};
    const BOT_TOKEN = process.env.BOT_TOKEN;
    if(!BOT_TOKEN){
      return { statusCode: 500, body: JSON.stringify({ valid:false, error:'BOT_TOKEN env missing' }) };
    }

    if(!verifyTelegramAuth(params, BOT_TOKEN)){
      return { statusCode: 401, body: JSON.stringify({ valid:false, error:'invalid_signature' }) };
    }

    const user = {
      id: params.id,
      first_name: params.first_name,
      last_name: params.last_name || '',
      username: params.username || '',
      photo_url: params.photo_url || '',
      auth_date: Number(params.auth_date) || Math.floor(Date.now()/1000)
    };

    const payload = Buffer.from(JSON.stringify(user), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', BOT_TOKEN).update(payload).digest('hex');
    const csrf = crypto.randomBytes(24).toString('hex');

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': [
          makeCookie('sess', payload, 60*60*24*7),
          makeCookie('sig', sig, 60*60*24*7),
          `csrf=${csrf}; Path=/; Secure; SameSite=Lax; Max-Age=${60*60*24*7}`
        ].join(', ')
      },
      body: JSON.stringify({ valid:true, user })
    };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ valid:false, error:String(e) }) };
  }
};
