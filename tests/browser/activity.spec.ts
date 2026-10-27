import { test, expect } from '@playwright/test';
const base='http://127.0.0.1:43627/v1/';
const token='a'.repeat(64);
test('Activity shows only opt-in read-only virtual history after native approval', async ({ page }) => {
  const hits:string[]=[];
  await page.route(base+'**', async route => {
    const path=route.request().url().slice(base.length);
    const method=route.request().method();
    hits.push(method+' '+path);
    let status=200;
    let body:unknown={};
    if(path==='health') body={platform:'windows',protocolVersion:'0.2',readOnly:true};
    else if(path==='access/request') body={token,scope:'devices:read',expiresInSeconds:1800};
    else if(path==='devices') body={devices:[],readOnly:true};
    else if(path.startsWith('simulations?limit=20')){
      expect(route.request().headers()['authorization']).toBe('Bearer '+token);
      body={simulationOnly:true,jobs:[{
        id:'3b1e0000-1111-2222-3333-444444444444',
        phase:'SIMULATED_SUCCEEDED',expectedBytes:4096,completedBytes:4096,verifiedBytes:4096,
        flushSimulated:true, failureCode:null,updatedAtMs:1700000000000,createdAtMs:1700000000000,
      }]};
    }else if(method==='OPTIONS') {status=204;}
    else {status=404;}
    await route.fulfill({status,contentType:'application/json',body:JSON.stringify(body),
      headers:{'access-control-allow-origin':'http://127.0.0.1:5173',
      'access-control-allow-headers':'authorization,content-type','access-control-allow-methods':'GET,POST,OPTIONS'}});
  });
  await page.goto('/app/workspace');
  await expect(page.getByText('Read-only device inventory')).toBeVisible();
  await page.getByRole('navigation').getByRole('button',{name:'Activity'}).click();
  await expect(page.getByRole('heading',{name:'Simulation activity'})).toBeVisible();
  await expect(page.getByTestId('simulation-job')).toHaveCount(1);
  await expect(page.getByText('SIMULATED SUCCEEDED')).toBeVisible();
  await expect(page.getByText('This is not evidence of a physical USB write.',{exact:false})).toBeVisible();
  await page.getByRole('button',{name:'Refresh history'}).click();
  await expect.poll(()=>hits.filter(x=>x==='GET simulations?limit=20').length).toBe(2);
  expect(hits).not.toContain('POST simulations');
  await page.getByRole('navigation').getByRole('button',{name:'Create USB'}).click();
  await expect(page.getByRole('button',{name:'Start writing'})).toBeDisabled();
});
test('Activity communicates offline agent and disabled simulation feed', async ({page})=>{
  await page.route(base+'**', async route => {
    if(route.request().url().endsWith('/health')) {
      await route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({platform:'windows',protocolVersion:'0.2'})});return;
    }
    if(route.request().url().endsWith('/access/request')) {
      await route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({token,scope:'devices:read'})});return;
    }
    if(route.request().url().endsWith('/devices')) {
      await route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({devices:[]})});return;
    }
    await route.fulfill({status:404,contentType:'application/json',body:JSON.stringify({error:'simulation_disabled'})});
  });
  await page.goto('/app/workspace');
  await expect(page.getByText('Read-only device inventory')).toBeVisible();
  await page.getByRole('navigation').getByRole('button',{name:'Activity'}).click();
  await expect(page.getByText('Developer simulation history is disabled on this agent.')).toBeVisible();
  await expect(page.getByTestId('simulation-job')).toHaveCount(0);
});
