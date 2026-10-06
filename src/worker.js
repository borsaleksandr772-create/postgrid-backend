import {handle} from './app.js';
import {database} from './db.js';
import {runQueue} from './publish.js';
export default {
 fetch:handle,
 scheduled(event,env,ctx){ctx.waitUntil(runQueue(env,database(env)));}
};
