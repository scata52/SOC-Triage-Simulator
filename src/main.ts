import './style.css';
import { App } from './ui/app.ts';

const root = document.getElementById('app');
if (!root) throw new Error('#app root not found');

new App(root);
