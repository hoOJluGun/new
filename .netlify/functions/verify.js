const crypto = require('crypto');

function parseCookies(h){
  const out = {};
  if(!h) return out;
  h.split(';').forEach(p => {
    const i = p.indexOf('=');
    if(i>-1){ out[p.slice(0,i).trim()] = p.slice(i+1).trim(); }
  });
  return out;
}

exports.handler = async (event) => {
  try{
    const BOT_TOKEN = process.env.BOT_TOKEN;
    if(!BOT_TOKEN) return { statusCode: 500, body: JSON.stringify({ valid:false, error:'BOT_TOKEN env missing' }) };

    const cookies = parseCookies(event.headers.cookie || '');
    const sess = cookies.sess;
    const sig = cookies.sig;

    if(!sess || !sig){
      return { statusCode: 200, body: JSON.stringify({ valid:false }) };
    }

    const expected = crypto.createHmac('sha256', BOT_TOKEN).update(sess).digest('hex');
    if(expected !== sig){
      return { statusCode: 200, body: JSON.stringify({ valid:false }) };
    }

    const user = JSON.parse(Buffer.from(sess, 'base64url').toString('utf8'));
    return { statusCode: 200, body: JSON.stringify({ valid:true, user }) };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ valid:false, error:String(e) }) };
  }
};
