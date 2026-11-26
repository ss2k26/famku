import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { applyTheme } from '$lib/theme';
import { loadRuntimeConfig } from '$lib/api';
import { loadCaptchaConfig } from '$lib/captcha.svelte';
import { refreshSession } from '$lib/auth.svelte';

applyTheme();
await loadRuntimeConfig(); // must finish first: it can change the API address
await Promise.allSettled([loadCaptchaConfig(), refreshSession()]);

mount(App, { target: document.getElementById('app')! });
