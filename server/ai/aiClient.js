const config = require('../config/app.config');
const logger = require('../utils/logger');

class AIClient {
  constructor() {
    this.geminiApiKey = config.ai.geminiApiKey;
    this.nvidiaApiKey = config.ai.nvidiaApiKey;
    this.openaiBaseUrl = config.ai.openaiBaseUrl;
    this.defaultModel = config.ai.defaultModel;
    this.maxTokens = config.ai.maxTokens;
    this.temperature = config.ai.temperature;
    this.retryAttempts = config.ai.retryAttempts;
    this.retryDelayMs = config.ai.retryDelayMs;
  }

  async complete(systemPrompt, userPrompt, options = {}) {
    const requestedModel = options.model || this.defaultModel;
    const isNvidiaModel = !requestedModel.toLowerCase().includes('gemini');

    try {
      // let result;
      if (isNvidiaModel) {
        result = await this._callNvidiaNim(requestedModel, systemPrompt, userPrompt, options);
      } else {
        result = await this._callGemini(requestedModel, systemPrompt, userPrompt, options);
      }
      // this._saveApiCall(requestedModel, systemPrompt, userPrompt, result);
      // return result;
    } catch (primaryError) {
      logger.warn(`Primary model (${requestedModel}) failed: ${primaryError.message}. Attempting fallback safe case...`);

      // Fallback safe case
      try {
        let result;
        let fallbackModel;
        if (isNvidiaModel) {
          // Fallback to Gemini
          fallbackModel = 'gemini-2.5-flash';
          result = await this._callGemini(fallbackModel, systemPrompt, userPrompt, options);
        } else {
          // Fallback to NVIDIA NIM 
          if (!this.nvidiaApiKey || this.nvidiaApiKey === 'your_nvidia_api_key_here') {
            throw new Error('NVIDIA API Key not configured for fallback.');
          }
          fallbackModel = 'mistralai/mistral-small-4-119b-2603';
          result = await this._callNvidiaNim(fallbackModel, systemPrompt, userPrompt, options);
        }
        // this._saveApiCall(fallbackModel, systemPrompt, userPrompt, result);
        // return result;
      } catch (fallbackError) {
        logger.error(`Fallback model also failed: ${fallbackError.message}`);
        throw new Error(`AI request failed after fallback. Primary error: ${primaryError.message}. Fallback error: ${fallbackError.message}`);
      }
    }
  }

  // _saveApiCall(model, systemPrompt, userPrompt, response) {
  //   try {
  //     const fs = require('fs');
  //     const path = require('path');
  //     const mocksDir = path.join(__dirname, '../../mocks/api_calls');
  //     if (!fs.existsSync(mocksDir)) {
  //       fs.mkdirSync(mocksDir, { recursive: true });
  //     }
  //     const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  //     // Attempt to parse the raw text output from the LLM into a JSON object
  //     // so the mock response perfectly mimics the frontend's expected data structure.
  //     let parsedData = response.text;
  //     try {
  //       if (response && response.text) {
  //         let text = response.text.trim();
  //         if (text.startsWith('```json')) {
  //           text = text.replace(/^```json\n?/, '').replace(/\n?```$/, '');
  //         } else if (text.startsWith('```')) {
  //           text = text.replace(/^```\n?/, '').replace(/\n?```$/, '');
  //         }
  //         parsedData = JSON.parse(text);
  //       }
  //     } catch (e) {
  //       // Fallback to raw text if it's not valid JSON
  //       parsedData = response.text;
  //     }

  //     // Wrap it in the standard responseFormatter structure
  //     const formattedResponse = {
  //       success: true,
  //       message: "AI request completed successfully",
  //       processingTimeMs: 420, // Arbitrary mock value
  //       data: parsedData
  //     };

  //     const filePath = path.join(mocksDir, `call_${timestamp}.json`);
  //     fs.writeFileSync(filePath, JSON.stringify(formattedResponse, null, 2));
  //     logger.debug(`Saved formatted API call to ${filePath}`);
  //   } catch (err) {
  //     logger.error(`Failed to save formatted API call: ${err.message}`);
  //   }
  // }

  async _callGemini(model, systemPrompt, userPrompt, options) {
    if (!this.geminiApiKey || this.geminiApiKey === 'your_gemini_api_key_here') {
      throw new Error('Gemini API key not configured.');
    }
    const maxTokens = options.maxTokens || this.maxTokens;
    const temperature = options.temperature ?? this.temperature;

    const requestBody = {
      contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
      systemInstruction: { parts: [{ text: systemPrompt }] },
      generationConfig: {
        temperature,
        maxOutputTokens: maxTokens,
        responseMimeType: 'application/json',
      },
    };

    let lastError;
    for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
      try {
        logger.debug(`Gemini API attempt ${attempt}/${this.retryAttempts}`, { model });
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${this.geminiApiKey}`;
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
          throw new Error(`Gemini API error (${response.status}): ${await response.text()}`);
        }

        const data = await response.json();
        const candidate = data.candidates?.[0];
        if (!candidate) throw new Error('No candidates returned from Gemini API');

        const responseText = candidate.content?.parts?.[0]?.text;
        if (!responseText) throw new Error('Empty response content from Gemini API');

        return {
          text: responseText,
          usage: data.usageMetadata || { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 }
        };
      } catch (error) {
        lastError = error;
        if (attempt < this.retryAttempts) {
          await new Promise(r => setTimeout(r, this.retryDelayMs * Math.pow(2, attempt - 1)));
        }
      }
    }
    throw new Error(lastError.message);
  }

  async _callNvidiaNim(model, systemPrompt, userPrompt, options) {
    if (!this.nvidiaApiKey || this.nvidiaApiKey === 'your_nvidia_api_key_here') {
      throw new Error('NVIDIA NIM API key not configured.');
    }
    const maxTokens = options.maxTokens || this.maxTokens;
    const temperature = options.temperature ?? this.temperature;

    const requestBody = {
      model: model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: temperature,
      max_tokens: maxTokens,
      response_format: { type: 'json_object' }
    };

    let lastError;
    for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
      try {
        let fetchUrl = this.openaiBaseUrl;
        if (!fetchUrl.endsWith('/chat/completions')) {
          fetchUrl = fetchUrl.replace(/\/+$/, '') + '/chat/completions';
        }

        logger.debug(`OpenAI-Compatible API attempt ${attempt}/${this.retryAttempts}`, { model, url: fetchUrl });
        const response = await fetch(fetchUrl, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.nvidiaApiKey}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
          throw new Error(`API error (${response.status}): ${await response.text()}`);
        }

        const data = await response.json();
        const choice = data.choices?.[0];
        if (!choice) throw new Error('No choices returned from API');

        const responseText = choice.message?.content;
        if (!responseText) throw new Error('Empty response content from API');

        return {
          text: responseText,
          usage: {
            promptTokenCount: data.usage?.prompt_tokens || 0,
            candidatesTokenCount: data.usage?.completion_tokens || 0,
            totalTokenCount: data.usage?.total_tokens || 0
          }
        };
      } catch (error) {
        lastError = error;
        if (attempt < this.retryAttempts) {
          await new Promise(r => setTimeout(r, this.retryDelayMs * Math.pow(2, attempt - 1)));
        }
      }
    }
    throw new Error(lastError.message);
  }

  isConfigured() {
    return Boolean(this.geminiApiKey && this.geminiApiKey !== 'your_gemini_api_key_here' || this.nvidiaApiKey && this.nvidiaApiKey !== 'your_nvidia_api_key_here');
  }

  getInfo() {
    return {
      provider: 'Multi-Model Routing',
      defaultModel: this.defaultModel,
      maxTokens: this.maxTokens,
      configured: this.isConfigured(),
    };
  }
}

module.exports = new AIClient();
