/**
 * Provider-Independent LLM Adapter Layer
 */

import { GoogleGenAI } from '@google/genai';

export interface LLMResponse {
  text: string;
  provider: string;
  model: string;
  latencyMs: number;
}

export interface LLMProviderAdapter {
  name: string;
  generateResponse(prompt: string, systemContext?: string): Promise<LLMResponse>;
}

// 1. Google Gemini Adapter
export class GeminiAdapter implements LLMProviderAdapter {
  name = 'Google Gemini';
  private client: GoogleGenAI | null = null;
  private model = 'gemini-3.1-flash-lite';

  constructor() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey !== 'MY_GEMINI_API_KEY' && apiKey.trim() !== '') {
      this.client = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    }
  }

  async generateResponse(prompt: string, systemContext?: string): Promise<LLMResponse> {
    const startTime = process.hrtime.bigint();

    // If client is initialized with real key, call Gemini API
    if (this.client) {
      try {
        const generatePromise = this.client.models.generateContent({
          model: this.model,
          contents: prompt,
          config: {
            systemInstruction:
              systemContext ||
              'You are a helpful, secure, and accurate AI assistant. You answer user queries clearly and concisely.',
          },
        });

        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Gemini downstream call exceeded 5000ms timeout')), 5000)
        );

        const response = await Promise.race([generatePromise, timeoutPromise]);

        const endTime = process.hrtime.bigint();
        const latencyMs = Number((Number(endTime - startTime) / 1_000_000).toFixed(2));

        return {
          text: response.text || 'No text content returned from Gemini model.',
          provider: 'Google Gemini (gemini-3.1-flash-lite)',
          model: this.model,
          latencyMs,
        };
      } catch (err: unknown) {
        const endTime = process.hrtime.bigint();
        const latencyMs = Number((Number(endTime - startTime) / 1_000_000).toFixed(2));
        return {
          text: `[Gemini Provider Error]: ${(err as Error).message || 'Failed to generate response'}`,
          provider: 'Google Gemini (gemini-3.1-flash-lite)',
          model: this.model,
          latencyMs,
        };
      }
    }

    // Fallback Mock response for safe demonstration
    const endTime = process.hrtime.bigint();
    const latencyMs = Number((Number(endTime - startTime) / 1_000_000).toFixed(2));

    const simulatedAnswer = generateSimulatedAnswer(prompt);
    return {
      text: simulatedAnswer,
      provider: 'Google Gemini (Simulated / Key Pending)',
      model: this.model,
      latencyMs: Math.max(85, latencyMs),
    };
  }
}

// 2. Mock / Local Adapter
export class LocalMockAdapter implements LLMProviderAdapter {
  name = 'Local Model Adapter';

  async generateResponse(prompt: string): Promise<LLMResponse> {
    const startTime = process.hrtime.bigint();
    const text = generateSimulatedAnswer(prompt);
    const endTime = process.hrtime.bigint();
    const latencyMs = Number((Number(endTime - startTime) / 1_000_000).toFixed(2));

    return {
      text,
      provider: 'Local Model Adapter',
      model: 'llama-3-8b-instruct-mock',
      latencyMs: Math.max(45, latencyMs),
    };
  }
}

function generateSimulatedAnswer(prompt: string): string {
  const p = prompt.toLowerCase();
  if (p.includes('dns')) {
    return 'Domain Name System (DNS) is the phonebook of the Internet. It translates human-friendly domain names (like example.com) into machine-readable IP addresses (like 192.0.2.1) so browsers can load Internet resources.';
  }
  if (p.includes('tcp') || p.includes('ip')) {
    return 'TCP/IP (Transmission Control Protocol/Internet Protocol) is the foundational suite of communication protocols used to interconnect network devices on the internet. TCP provides reliable, ordered data stream delivery, while IP handles addressing and packet routing.';
  }
  if (p.includes('firewall')) {
    return 'A firewall is a network security device or software filter that monitors and filters incoming and outgoing network traffic based on an organization’s previously established security policies. It creates a barrier between a trusted network and untrusted outside networks.';
  }
  if (p.includes('factorial') || p.includes('python')) {
    return 'Here is a Python program to calculate factorial:\n\n```python\ndef factorial(n):\n    if n < 0:\n        raise ValueError("Factorial is not defined for negative numbers")\n    return 1 if n <= 1 else n * factorial(n - 1)\n\nprint(factorial(5)) # Output: 120\n```';
  }
  if (p.includes('weather')) {
    return 'The current conditions are clear and sunny with a temperature of 22°C (72°F), light westerly winds, and 45% relative humidity.';
  }
  return `This prompt passed all security checks in the LLM Prompt Injection Firewall and was successfully processed by the downstream language model.\n\nInput summary: "${prompt.slice(0, 100)}${prompt.length > 100 ? '...' : ''}"`;
}
