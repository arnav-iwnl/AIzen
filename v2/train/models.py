"""Model architectures for AIzen v2.

Three heads over a char-level sequence encoder:
  - attack_type (index 0 == "none" / benign; other indices == attack subtype)
  - category
  - severity

is_attack is derived at runtime as (attack_type != "none"). Using a single
attack_type head keeps the binary decision and the subtype in one place.
"""
import math

import torch
import torch.nn as nn

import config


class MultiHeadSequenceNet(nn.Module):
    def __init__(self, vocab_size, n_attack, n_cat, n_sev):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, config.EMB_DIM, padding_idx=0)

        if config.MODEL == "transformer":
            enc_layer = nn.TransformerEncoderLayer(
                d_model=config.EMB_DIM, nhead=4, dim_feedforward=config.HIDDEN * 2,
                dropout=config.DROPOUT, batch_first=True,
            )
            self.encoder = nn.TransformerEncoder(enc_layer, num_layers=config.LAYERS)
            self.pool = "cls"
            self.cls_token = nn.Parameter(torch.zeros(1, 1, config.EMB_DIM))
            nn.init.normal_(self.cls_token, std=0.02)
        else:  # lstm
            self.encoder = nn.LSTM(config.EMB_DIM, config.HIDDEN, num_layers=config.LAYERS,
                                   batch_first=True, dropout=config.DROPOUT if config.LAYERS > 1 else 0.0,
                                   bidirectional=True)
            self.pool = "mean"
            enc_out = config.HIDDEN * 2

        head_in = config.EMB_DIM if self.pool == "cls" else enc_out
        self.drop = nn.Dropout(config.DROPOUT)
        self.attack_head = nn.Linear(head_in, n_attack)
        self.cat_head = nn.Linear(head_in, n_cat)
        self.sev_head = nn.Linear(head_in, n_sev)

    def forward(self, ids, mask=None):  # ids: (B, L)
        x = self.embed(ids)  # (B, L, D)
        if self.pool == "cls":
            cls = self.cls_token.expand(ids.size(0), -1, -1)
            x = torch.cat([cls, x], dim=1)
            x = self.encoder(x)
            pooled = x[:, 0]
        else:
            x, _ = self.encoder(x)
            if mask is None:
                # Derive the padding mask from the ids (PAD id is 0) instead of
                # averaging PAD positions into the pooled vector. The old
                # `x.mean(dim=1)` diluted the representation: a typical 176-char
                # log line contributed ~31% of a 256-wide window, so the vector
                # was length-dependent and shifted off-manifold on log formats
                # with different line lengths. Deriving it here (rather than
                # adding a second graph input) keeps the ONNX signature at one
                # input, so v2/runtime/onnx_classifier.js is unchanged.
                mask = (ids != 0).unsqueeze(-1).to(x.dtype)
            m = mask.unsqueeze(-1).to(x.dtype) if mask.dim() == 2 else mask
            pooled = (x * m).sum(dim=1) / (m.sum(dim=1) + 1e-8)
        pooled = self.drop(pooled)
        return {
            "attack": self.attack_head(pooled),
            "category": self.cat_head(pooled),
            "severity": self.sev_head(pooled),
        }


def build_model(meta):
    vocab = 258  # bytes 0..255 + PAD + UNK
    return MultiHeadSequenceNet(
        vocab_size=vocab,
        n_attack=len(meta["attack_index"]),
        n_cat=len(meta["category_index"]),
        n_sev=len(meta["severity_index"]),
    )
