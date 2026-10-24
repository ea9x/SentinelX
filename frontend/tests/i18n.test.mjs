import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const parser=require('@babel/parser');
const traverse=require('@babel/traverse').default;
const b=require('@babel/types');
const stored=new Map();
globalThis.localStorage={getItem:(key)=>stored.get(key)??null,setItem:(key,value)=>stored.set(key,value)};
globalThis.document={documentElement:{}};
globalThis.window={addEventListener(){}};
const {t,setLanguage,getLanguage,getLocale}=await import('../src/i18n/language.js');
const {ar}=await import('../src/i18n/ar.js');
const root=fileURLToPath(new URL('../src/',import.meta.url));
function modules(folder){return readdirSync(folder,{withFileTypes:true}).flatMap(item=>item.isDirectory()?modules(path.join(folder,item.name)):/\.jsx?$/.test(item.name)?[path.join(folder,item.name)]:[]);}

test('switches both ways and persists only the supported preference',()=>{
    assert.equal(getLanguage(),'en');assert.equal(t('Dashboard'),'Dashboard');
    setLanguage('ar');assert.equal(t('Dashboard'),'لوحة التحكم');assert.equal(getLocale(),'ar');
    assert.equal(document.documentElement.dir,'rtl');assert.equal(document.documentElement.lang,'ar');
    assert.equal(stored.get('sentinelx.language'),'ar');
    setLanguage('en');assert.equal(t('Dashboard'),'Dashboard');assert.equal(document.documentElement.dir,'ltr');
});
test('invalid language values do not change the setting',()=>{
    setLanguage('en');setLanguage('other');assert.equal(getLanguage(),'en');
});
test('dynamic scan notifications translate without treating a regex as text',()=>{
    setLanguage('ar');
    assert.equal(t('Full Scan scan incomplete'),'فحص Full Scan غير مكتمل');
    assert.equal(t('⚠ Scan result: Full Scan'),'⚠ نتيجة الفحص: Full Scan');
    assert.equal(t('  Finding #17  '),'  النتيجة رقم 17  ');
    assert.equal(t('constructor',['literal']),'constructor');
    assert.equal(t('__proto__'),'__proto__');
    setLanguage('en');
});
test('interpolates UI labels without modifying resource data',()=>{
    setLanguage('ar');assert.equal(t('{0}/{1} services available',[6,6]),'6/6 خدمات متاحة');
    assert.equal(t('Running NMAP'),'جارٍ تشغيل NMAP');
    const resource='https://example.test/path?language=en&token=literal';assert.equal(t(resource),resource);
    assert.equal(t('Scan {0}', ['literal-{1}']), 'Scan literal-{1}');
    assert.equal(t(47),47);setLanguage('en');
});
test('every literal UI translation has a catalog entry or an explicit brand exemption',()=>{
    const exempt=new Set(['SentinelX','Nmap','ZAP','Nuclei','WhatWeb','SSLyze','CVE','CWE','TLS','HTTPS','HTTP','JSON','PDF','URL','JWT','API','IP','English']);
    const missing=new Set();
    for(const file of modules(root)){
        const ast=parser.parse(readFileSync(file,'utf8'),{sourceType:'module',plugins:['jsx']});
        traverse(ast,{CallExpression(p){
            if(b.isIdentifier(p.node.callee,{name:'t'})&&b.isStringLiteral(p.node.arguments[0])){
                const key=p.node.arguments[0].value.trim();if(/[A-Za-z]/.test(key)&&!ar[key]&&!exempt.has(key))missing.add(key);
            }
        }});
    }
    assert.deepEqual([...missing],[]);
});
test('translation never changes API enum comparisons or option values',()=>{
    for(const file of modules(root)){
        const ast=parser.parse(readFileSync(file,'utf8'),{sourceType:'module',plugins:['jsx']});
        traverse(ast,{
            BinaryExpression(p){
                if(['===','!==','==','!='].includes(p.node.operator)){
                    for(const operand of [p.node.left,p.node.right])assert.ok(!(b.isCallExpression(operand)&&b.isIdentifier(operand.callee,{name:'t'})),file);
                }
            },
            JSXOpeningElement(p){
                if(p.node.name.name!=='option')return;
                const value=p.node.attributes.find(a=>a.name?.name==='value');assert.ok(value,file);
                if(b.isJSXExpressionContainer(value.value))assert.ok(!(b.isCallExpression(value.value.expression)&&b.isIdentifier(value.value.expression.callee,{name:'t'})),file);
            }
        });
    }
});
test('profile has no upload input, photo preview or upload request',()=>{
    const source=readFileSync(path.join(root,'pages/Profile.jsx'),'utf8');
    for(const removed of ['type="file"','Upload Photo','Profile photo','uploadPhoto','photoPreviewOpen','/auth/avatar'])assert.ok(!source.includes(removed),removed);
});

test('translation calls never resolve to shadowing loop variables',()=>{
    for(const file of modules(root)){
        const ast=parser.parse(readFileSync(file,'utf8'),{sourceType:'module',plugins:['jsx']});
        traverse(ast,{CallExpression(p){
            if(!b.isIdentifier(p.node.callee,{name:'t'}))return;
            const binding=p.scope.getBinding('t');
            assert.ok(binding && binding.path.isImportSpecifier(),file+': shadowed translator');
        }});
    }
});
