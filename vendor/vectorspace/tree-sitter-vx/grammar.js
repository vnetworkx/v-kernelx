module.exports = grammar({
  name: 'vx',

  extras: $ => [
    /[\s\uFEFF\xA0]/,
    $.comment
  ],

  word: $ => $.identifier,

  rules: {
    source_file: $ => repeat($.statement),

    statement: $ => choice(
      $.vector_decl,
      $.wallet_decl,
      $.certify_stmt,
      $.transfer_stmt,
      $.drain_stmt,
      $.project_stmt,
      $.reconstruct_stmt,
      $.query_stmt,
      $.record_stmt,
      $.contract_decl
    ),

    vector_decl: $ => seq(
      'vector',
      $.identifier,
      ':',
      $.type_tag,
      '=',
      $.vector_literal,
      ';'
    ),

    wallet_decl: $ => seq(
      'wallet',
      $.identifier,
      '=',
      'bind',
      '(',
      $.scalar,
      ')',
      ';'
    ),

    certify_stmt: $ => seq(
      'certify',
      $.identifier,
      'with',
      $.context_expr,
      ';'
    ),

    transfer_stmt: $ => seq(
      'transfer',
      $.identifier,
      'to',
      $.identifier,
      'amount',
      $.expression,
      optional($.drain_clause),
      optional($.policy_clause),
      ';'
    ),

    drain_stmt: $ => seq(
      'drain',
      $.identifier,
      'by',
      $.expression,
      ';'
    ),

    project_stmt: $ => seq(
      'project',
      $.identifier,
      'into',
      $.identifier,
      'amount',
      $.expression,
      optional($.policy_clause),
      ';'
    ),

    reconstruct_stmt: $ => seq(
      'reconstruct',
      $.identifier,
      'from',
      $.identifier,
      ';'
    ),

    query_stmt: $ => seq('query', $.expression, ';'),
    record_stmt: $ => seq('record', $.expression, ';'),

    contract_decl: $ => seq(
      'contract',
      $.identifier,
      '{',
      repeat($.contract_action),
      '}'
    ),

    contract_action: $ => seq(
      'action',
      $.identifier,
      optional($.action_args),
      ';'
    ),

    action_args: $ => seq(
      '(',
      optional($.named_argument_list),
      ')'
    ),

    named_argument_list: $ => seq(
      $.named_argument,
      repeat(seq(',', $.named_argument))
    ),

    named_argument: $ => choice(
      seq($.identifier, '=', $.expression),
      $.expression
    ),

    drain_clause: $ => seq('drain', $.expression),
    policy_clause: $ => seq('policy', $.expression),

    context_expr: $ => seq(
      'ctx',
      '(',
      optional($.named_argument_list),
      ')'
    ),

    vector_type: $ => $.type_tag,
    type_tag: $ => choice('position', 'free', 'bound', 'unit', 'zero', 'spatial'),

    vector_literal: $ => seq(
      '(',
      optional($.integer_list),
      ')'
    ),

    integer_list: $ => seq(
      $.integer,
      repeat(seq(',', $.integer))
    ),

    expression: $ => choice(
      $.integer,
      $.string,
      $.identifier,
      $.path,
      $.call,
      seq('(', $.expression, ')')
    ),

    path: $ => seq($.identifier, repeat1(seq('.', $.identifier))),
    call: $ => seq($.identifier, '(', optional($.named_argument_list), ')'),

    scalar: $ => choice($.integer, $.identifier, $.string),

    comment: $ => token(choice(
      seq('//', /[^\n]*/),
      seq('#', /[^\n]*/)
    )),

    identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/,
    integer: $ => /[0-9]+/,
    string: $ => token(seq(
      '"',
      repeat(choice(/[^"\\\n]/, /\\./)),
      '"'
    ))
  }
});