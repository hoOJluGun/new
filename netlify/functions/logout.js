function expire(name){ return `${name}=; Path=/; Max-Age=0; Secure; SameSite=Lax`; }

exports.handler = async () => {
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': [expire('sess'), expire('sig'), expire('csrf')].join(', ')
    },
    body: JSON.stringify({ ok:true })
  };
};
