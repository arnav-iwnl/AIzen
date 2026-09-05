const config = require('../config/app.config');
const logger = require('../utils/logger');

class AIClient {
  constructor() {
    this.apiKey = config.ai.apiKey;
    this.openaiBaseUrl = config.ai.openaiBaseUrl;
    this.defaultModel = config.ai.defaultModel;
    this.maxTokens = config.ai.maxTokens;
    this.temperature = config.ai.temperature;
    this.retryAttempts = config.ai.retryAttempts;
    this.retryDelayMs = config.ai.retryDelayMs;
  }

  async complete(systemPrompt, userPrompt, options = {}) {
    if (!this.isConfigured()) {
      throw new Error('AI client not configured. Set OPENAI_API_KEY to enable LLM features.');
    }

    const model = options.model || this.defaultModel;
    const maxTokens = options.maxTokens || this.maxTokens;
    const temperature = options.temperature ?? this.temperature;

    const requestBody = {
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature,
      max_tokens: maxTokens
    };

    let lastError;
    for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
      try {
        const url = this.openaiBaseUrl;
        logger.debug(`AI API attempt ${attempt}/${this.retryAttempts}`, { url, model });
        const response = await fetch(url, {
          method: 'POST',
          signal: AbortSignal.timeout(45000),
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
          throw new Error(`AI API error (${response.status}): ${await response.text()}`);
        }

        const data = await response.json();
        const choice = data.choices?.[0];
        const responseText = choice?.message?.content || data?.output || '';

        const result = { text: responseText, usage: data.usage || null };
        this._saveApiCall(model, systemPrompt, userPrompt, result);
        return result;
      } catch (err) {
        lastError = err;
        if (attempt < this.retryAttempts) {
          await new Promise(r => setTimeout(r, this.retryDelayMs * Math.pow(2, attempt - 1)));
        }
      }
    }
    throw new Error(lastError.message);
  }

  _saveApiCall(model, systemPrompt, userPrompt, response) {
    try {
      const fs = require('fs');
      const path = require('path');
      const mocksDir = path.join(__dirname, '../../mocks/api_calls');
      if (!fs.existsSync(mocksDir)) {
        fs.mkdirSync(mocksDir, { recursive: true });
      }
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  
      let parsedData = response.text;
      try {
        if (response && response.text) {
          let text = response.text.trim();
          if (text.startsWith('```json')) {
            text = text.replace(/^```json\n?/, '').replace(/\n?```$/, '');
          } else if (text.startsWith('```')) {
            text = text.replace(/^```\n?/, '').replace(/\n?```$/, '');
          }
          parsedData = JSON.parse(text);
        }
      } catch (e) {
        parsedData = response.text;
      }
  
      const formattedResponse = {
        success: true,
        message: "AI request completed successfully",
        processingTimeMs: 420,
        data: parsedData
      };
  
      const filePath = path.join(mocksDir, `call_${timestamp}.json`);
      fs.writeFileSync(filePath, JSON.stringify(formattedResponse, null, 2));
      logger.debug(`Saved formatted API call to ${filePath}`);
    } catch (err) {
      logger.error(`Failed to save formatted API call: ${err.message}`);
    }
  }


  isConfigured() {
    return Boolean(this.apiKey && this.apiKey !== 'your_api_key_here');
  }

  getInfo() {
    return {
      provider: 'OpenAI-Compatible',
      defaultModel: this.defaultModel,
      maxTokens: this.maxTokens,
      configured: this.isConfigured(),
    };
  }
}

module.exports = new AIClient();
