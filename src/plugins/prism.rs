use std::collections::HashMap;

use crate::plugins::plugin::PastebinPlugin;

pub fn new<'r>() -> PastebinPlugin<'r> {
    PastebinPlugin {
        css_imports: vec!["/static/prism.css"],
        js_imports: vec!["/static/prism.js"],
        js_init: Some(
            "var holder = $('#pastebin-code-block:first').get(0); \
            if (holder) { Prism.highlightElement(holder); }",
        ),
        static_resources: load_static_resources! {
            "/static/prism.js" => "../../static/prism.js",
            "/static/prism.css" =>"../../static/prism.css",
            "/static/prism-one-light.css" =>"../../static/prism-one-light.css",
            "/static/prism-material-dark.css" =>"../../static/prism-material-dark.css",
            "/static/components/prism-abap.min.js" => "../../static/components/prism-abap.min.js",
            "/static/components/prism-abnf.min.js" => "../../static/components/prism-abnf.min.js",
            "/static/components/prism-actionscript.min.js" => "../../static/components/prism-actionscript.min.js",
            "/static/components/prism-ada.min.js" => "../../static/components/prism-ada.min.js",
            "/static/components/prism-agda.min.js" => "../../static/components/prism-agda.min.js",
            "/static/components/prism-al.min.js" => "../../static/components/prism-al.min.js",
            "/static/components/prism-antlr4.min.js" => "../../static/components/prism-antlr4.min.js",
            "/static/components/prism-apacheconf.min.js" => "../../static/components/prism-apacheconf.min.js",
            "/static/components/prism-apex.min.js" => "../../static/components/prism-apex.min.js",
            "/static/components/prism-apl.min.js" => "../../static/components/prism-apl.min.js",
            "/static/components/prism-applescript.min.js" => "../../static/components/prism-applescript.min.js",
            "/static/components/prism-aql.min.js" => "../../static/components/prism-aql.min.js",
            "/static/components/prism-arduino.min.js" => "../../static/components/prism-arduino.min.js",
            "/static/components/prism-arff.min.js" => "../../static/components/prism-arff.min.js",
            "/static/components/prism-armasm.min.js" => "../../static/components/prism-armasm.min.js",
            "/static/components/prism-arturo.min.js" => "../../static/components/prism-arturo.min.js",
            "/static/components/prism-asciidoc.min.js" => "../../static/components/prism-asciidoc.min.js",
            "/static/components/prism-asm6502.min.js" => "../../static/components/prism-asm6502.min.js",
            "/static/components/prism-asmatmel.min.js" => "../../static/components/prism-asmatmel.min.js",
            "/static/components/prism-aspnet.min.js" => "../../static/components/prism-aspnet.min.js",
            "/static/components/prism-autohotkey.min.js" => "../../static/components/prism-autohotkey.min.js",
            "/static/components/prism-autoit.min.js" => "../../static/components/prism-autoit.min.js",
            "/static/components/prism-avisynth.min.js" => "../../static/components/prism-avisynth.min.js",
            "/static/components/prism-avro-idl.min.js" => "../../static/components/prism-avro-idl.min.js",
            "/static/components/prism-awk.min.js" => "../../static/components/prism-awk.min.js",
            "/static/components/prism-bash.min.js" => "../../static/components/prism-bash.min.js",
            "/static/components/prism-basic.min.js" => "../../static/components/prism-basic.min.js",
            "/static/components/prism-batch.min.js" => "../../static/components/prism-batch.min.js",
            "/static/components/prism-bbcode.min.js" => "../../static/components/prism-bbcode.min.js",
            "/static/components/prism-bbj.min.js" => "../../static/components/prism-bbj.min.js",
            "/static/components/prism-bicep.min.js" => "../../static/components/prism-bicep.min.js",
            "/static/components/prism-birb.min.js" => "../../static/components/prism-birb.min.js",
            "/static/components/prism-bison.min.js" => "../../static/components/prism-bison.min.js",
            "/static/components/prism-bnf.min.js" => "../../static/components/prism-bnf.min.js",
            "/static/components/prism-bqn.min.js" => "../../static/components/prism-bqn.min.js",
            "/static/components/prism-brainfuck.min.js" => "../../static/components/prism-brainfuck.min.js",
            "/static/components/prism-brightscript.min.js" => "../../static/components/prism-brightscript.min.js",
            "/static/components/prism-bro.min.js" => "../../static/components/prism-bro.min.js",
            "/static/components/prism-bsl.min.js" => "../../static/components/prism-bsl.min.js",
            "/static/components/prism-cfscript.min.js" => "../../static/components/prism-cfscript.min.js",
            "/static/components/prism-chaiscript.min.js" => "../../static/components/prism-chaiscript.min.js",
            "/static/components/prism-cilkc.min.js" => "../../static/components/prism-cilkc.min.js",
            "/static/components/prism-cilkcpp.min.js" => "../../static/components/prism-cilkcpp.min.js",
            "/static/components/prism-cil.min.js" => "../../static/components/prism-cil.min.js",
            "/static/components/prism-clike.min.js" => "../../static/components/prism-clike.min.js",
            "/static/components/prism-clojure.min.js" => "../../static/components/prism-clojure.min.js",
            "/static/components/prism-cmake.min.js" => "../../static/components/prism-cmake.min.js",
            "/static/components/prism-c.min.js" => "../../static/components/prism-c.min.js",
            "/static/components/prism-cobol.min.js" => "../../static/components/prism-cobol.min.js",
            "/static/components/prism-coffeescript.min.js" => "../../static/components/prism-coffeescript.min.js",
            "/static/components/prism-concurnas.min.js" => "../../static/components/prism-concurnas.min.js",
            "/static/components/prism-cooklang.min.js" => "../../static/components/prism-cooklang.min.js",
            "/static/components/prism-coq.min.js" => "../../static/components/prism-coq.min.js",
            "/static/components/prism-cpp.min.js" => "../../static/components/prism-cpp.min.js",
            "/static/components/prism-crystal.min.js" => "../../static/components/prism-crystal.min.js",
            "/static/components/prism-csharp.min.js" => "../../static/components/prism-csharp.min.js",
            "/static/components/prism-cshtml.min.js" => "../../static/components/prism-cshtml.min.js",
            "/static/components/prism-csp.min.js" => "../../static/components/prism-csp.min.js",
            "/static/components/prism-css-extras.min.js" => "../../static/components/prism-css-extras.min.js",
            "/static/components/prism-css.min.js" => "../../static/components/prism-css.min.js",
            "/static/components/prism-csv.min.js" => "../../static/components/prism-csv.min.js",
            "/static/components/prism-cue.min.js" => "../../static/components/prism-cue.min.js",
            "/static/components/prism-cypher.min.js" => "../../static/components/prism-cypher.min.js",
            "/static/components/prism-dart.min.js" => "../../static/components/prism-dart.min.js",
            "/static/components/prism-dataweave.min.js" => "../../static/components/prism-dataweave.min.js",
            "/static/components/prism-dax.min.js" => "../../static/components/prism-dax.min.js",
            "/static/components/prism-dhall.min.js" => "../../static/components/prism-dhall.min.js",
            "/static/components/prism-diff.min.js" => "../../static/components/prism-diff.min.js",
            "/static/components/prism-django.min.js" => "../../static/components/prism-django.min.js",
            "/static/components/prism-d.min.js" => "../../static/components/prism-d.min.js",
            "/static/components/prism-dns-zone-file.min.js" => "../../static/components/prism-dns-zone-file.min.js",
            "/static/components/prism-docker.min.js" => "../../static/components/prism-docker.min.js",
            "/static/components/prism-dot.min.js" => "../../static/components/prism-dot.min.js",
            "/static/components/prism-ebnf.min.js" => "../../static/components/prism-ebnf.min.js",
            "/static/components/prism-editorconfig.min.js" => "../../static/components/prism-editorconfig.min.js",
            "/static/components/prism-eiffel.min.js" => "../../static/components/prism-eiffel.min.js",
            "/static/components/prism-ejs.min.js" => "../../static/components/prism-ejs.min.js",
            "/static/components/prism-elixir.min.js" => "../../static/components/prism-elixir.min.js",
            "/static/components/prism-elm.min.js" => "../../static/components/prism-elm.min.js",
            "/static/components/prism-erb.min.js" => "../../static/components/prism-erb.min.js",
            "/static/components/prism-erlang.min.js" => "../../static/components/prism-erlang.min.js",
            "/static/components/prism-etlua.min.js" => "../../static/components/prism-etlua.min.js",
            "/static/components/prism-excel-formula.min.js" => "../../static/components/prism-excel-formula.min.js",
            "/static/components/prism-factor.min.js" => "../../static/components/prism-factor.min.js",
            "/static/components/prism-false.min.js" => "../../static/components/prism-false.min.js",
            "/static/components/prism-firestore-security-rules.min.js" => "../../static/components/prism-firestore-security-rules.min.js",
            "/static/components/prism-flow.min.js" => "../../static/components/prism-flow.min.js",
            "/static/components/prism-fortran.min.js" => "../../static/components/prism-fortran.min.js",
            "/static/components/prism-fsharp.min.js" => "../../static/components/prism-fsharp.min.js",
            "/static/components/prism-ftl.min.js" => "../../static/components/prism-ftl.min.js",
            "/static/components/prism-gap.min.js" => "../../static/components/prism-gap.min.js",
            "/static/components/prism-gcode.min.js" => "../../static/components/prism-gcode.min.js",
            "/static/components/prism-gdscript.min.js" => "../../static/components/prism-gdscript.min.js",
            "/static/components/prism-gedcom.min.js" => "../../static/components/prism-gedcom.min.js",
            "/static/components/prism-gettext.min.js" => "../../static/components/prism-gettext.min.js",
            "/static/components/prism-gherkin.min.js" => "../../static/components/prism-gherkin.min.js",
            "/static/components/prism-git.min.js" => "../../static/components/prism-git.min.js",
            "/static/components/prism-glsl.min.js" => "../../static/components/prism-glsl.min.js",
            "/static/components/prism-gml.min.js" => "../../static/components/prism-gml.min.js",
            "/static/components/prism-gn.min.js" => "../../static/components/prism-gn.min.js",
            "/static/components/prism-go.min.js" => "../../static/components/prism-go.min.js",
            "/static/components/prism-go-module.min.js" => "../../static/components/prism-go-module.min.js",
            "/static/components/prism-gradle.min.js" => "../../static/components/prism-gradle.min.js",
            "/static/components/prism-graphql.min.js" => "../../static/components/prism-graphql.min.js",
            "/static/components/prism-groovy.min.js" => "../../static/components/prism-groovy.min.js",
            "/static/components/prism-haml.min.js" => "../../static/components/prism-haml.min.js",
            "/static/components/prism-handlebars.min.js" => "../../static/components/prism-handlebars.min.js",
            "/static/components/prism-haskell.min.js" => "../../static/components/prism-haskell.min.js",
            "/static/components/prism-haxe.min.js" => "../../static/components/prism-haxe.min.js",
            "/static/components/prism-hcl.min.js" => "../../static/components/prism-hcl.min.js",
            "/static/components/prism-hlsl.min.js" => "../../static/components/prism-hlsl.min.js",
            "/static/components/prism-hoon.min.js" => "../../static/components/prism-hoon.min.js",
            "/static/components/prism-hpkp.min.js" => "../../static/components/prism-hpkp.min.js",
            "/static/components/prism-hsts.min.js" => "../../static/components/prism-hsts.min.js",
            "/static/components/prism-http.min.js" => "../../static/components/prism-http.min.js",
            "/static/components/prism-ichigojam.min.js" => "../../static/components/prism-ichigojam.min.js",
            "/static/components/prism-icon.min.js" => "../../static/components/prism-icon.min.js",
            "/static/components/prism-icu-message-format.min.js" => "../../static/components/prism-icu-message-format.min.js",
            "/static/components/prism-idris.min.js" => "../../static/components/prism-idris.min.js",
            "/static/components/prism-iecst.min.js" => "../../static/components/prism-iecst.min.js",
            "/static/components/prism-ignore.min.js" => "../../static/components/prism-ignore.min.js",
            "/static/components/prism-inform7.min.js" => "../../static/components/prism-inform7.min.js",
            "/static/components/prism-ini.min.js" => "../../static/components/prism-ini.min.js",
            "/static/components/prism-io.min.js" => "../../static/components/prism-io.min.js",
            "/static/components/prism-javadoclike.min.js" => "../../static/components/prism-javadoclike.min.js",
            "/static/components/prism-javadoc.min.js" => "../../static/components/prism-javadoc.min.js",
            "/static/components/prism-java.min.js" => "../../static/components/prism-java.min.js",
            "/static/components/prism-javascript.min.js" => "../../static/components/prism-javascript.min.js",
            "/static/components/prism-javastacktrace.min.js" => "../../static/components/prism-javastacktrace.min.js",
            "/static/components/prism-jexl.min.js" => "../../static/components/prism-jexl.min.js",
            "/static/components/prism-j.min.js" => "../../static/components/prism-j.min.js",
            "/static/components/prism-jolie.min.js" => "../../static/components/prism-jolie.min.js",
            "/static/components/prism-jq.min.js" => "../../static/components/prism-jq.min.js",
            "/static/components/prism-jsdoc.min.js" => "../../static/components/prism-jsdoc.min.js",
            "/static/components/prism-js-extras.min.js" => "../../static/components/prism-js-extras.min.js",
            "/static/components/prism-json5.min.js" => "../../static/components/prism-json5.min.js",
            "/static/components/prism-json.min.js" => "../../static/components/prism-json.min.js",
            "/static/components/prism-jsonp.min.js" => "../../static/components/prism-jsonp.min.js",
            "/static/components/prism-jsstacktrace.min.js" => "../../static/components/prism-jsstacktrace.min.js",
            "/static/components/prism-js-templates.min.js" => "../../static/components/prism-js-templates.min.js",
            "/static/components/prism-jsx.min.js" => "../../static/components/prism-jsx.min.js",
            "/static/components/prism-julia.min.js" => "../../static/components/prism-julia.min.js",
            "/static/components/prism-keepalived.min.js" => "../../static/components/prism-keepalived.min.js",
            "/static/components/prism-keyman.min.js" => "../../static/components/prism-keyman.min.js",
            "/static/components/prism-kotlin.min.js" => "../../static/components/prism-kotlin.min.js",
            "/static/components/prism-kumir.min.js" => "../../static/components/prism-kumir.min.js",
            "/static/components/prism-kusto.min.js" => "../../static/components/prism-kusto.min.js",
            "/static/components/prism-latex.min.js" => "../../static/components/prism-latex.min.js",
            "/static/components/prism-latte.min.js" => "../../static/components/prism-latte.min.js",
            "/static/components/prism-less.min.js" => "../../static/components/prism-less.min.js",
            "/static/components/prism-lilypond.min.js" => "../../static/components/prism-lilypond.min.js",
            "/static/components/prism-linker-script.min.js" => "../../static/components/prism-linker-script.min.js",
            "/static/components/prism-liquid.min.js" => "../../static/components/prism-liquid.min.js",
            "/static/components/prism-lisp.min.js" => "../../static/components/prism-lisp.min.js",
            "/static/components/prism-livescript.min.js" => "../../static/components/prism-livescript.min.js",
            "/static/components/prism-llvm.min.js" => "../../static/components/prism-llvm.min.js",
            "/static/components/prism-log.min.js" => "../../static/components/prism-log.min.js",
            "/static/components/prism-lolcode.min.js" => "../../static/components/prism-lolcode.min.js",
            "/static/components/prism-lua.min.js" => "../../static/components/prism-lua.min.js",
            "/static/components/prism-magma.min.js" => "../../static/components/prism-magma.min.js",
            "/static/components/prism-makefile.min.js" => "../../static/components/prism-makefile.min.js",
            "/static/components/prism-markdown.min.js" => "../../static/components/prism-markdown.min.js",
            "/static/components/prism-markup.min.js" => "../../static/components/prism-markup.min.js",
            "/static/components/prism-markup-templating.min.js" => "../../static/components/prism-markup-templating.min.js",
            "/static/components/prism-mata.min.js" => "../../static/components/prism-mata.min.js",
            "/static/components/prism-matlab.min.js" => "../../static/components/prism-matlab.min.js",
            "/static/components/prism-maxscript.min.js" => "../../static/components/prism-maxscript.min.js",
            "/static/components/prism-mel.min.js" => "../../static/components/prism-mel.min.js",
            "/static/components/prism-mermaid.min.js" => "../../static/components/prism-mermaid.min.js",
            "/static/components/prism-metafont.min.js" => "../../static/components/prism-metafont.min.js",
            "/static/components/prism-mizar.min.js" => "../../static/components/prism-mizar.min.js",
            "/static/components/prism-mongodb.min.js" => "../../static/components/prism-mongodb.min.js",
            "/static/components/prism-monkey.min.js" => "../../static/components/prism-monkey.min.js",
            "/static/components/prism-moonscript.min.js" => "../../static/components/prism-moonscript.min.js",
            "/static/components/prism-n1ql.min.js" => "../../static/components/prism-n1ql.min.js",
            "/static/components/prism-n4js.min.js" => "../../static/components/prism-n4js.min.js",
            "/static/components/prism-nand2tetris-hdl.min.js" => "../../static/components/prism-nand2tetris-hdl.min.js",
            "/static/components/prism-naniscript.min.js" => "../../static/components/prism-naniscript.min.js",
            "/static/components/prism-nasm.min.js" => "../../static/components/prism-nasm.min.js",
            "/static/components/prism-neon.min.js" => "../../static/components/prism-neon.min.js",
            "/static/components/prism-nevod.min.js" => "../../static/components/prism-nevod.min.js",
            "/static/components/prism-nginx.min.js" => "../../static/components/prism-nginx.min.js",
            "/static/components/prism-nim.min.js" => "../../static/components/prism-nim.min.js",
            "/static/components/prism-nix.min.js" => "../../static/components/prism-nix.min.js",
            "/static/components/prism-nsis.min.js" => "../../static/components/prism-nsis.min.js",
            "/static/components/prism-objectivec.min.js" => "../../static/components/prism-objectivec.min.js",
            "/static/components/prism-ocaml.min.js" => "../../static/components/prism-ocaml.min.js",
            "/static/components/prism-odin.min.js" => "../../static/components/prism-odin.min.js",
            "/static/components/prism-opencl.min.js" => "../../static/components/prism-opencl.min.js",
            "/static/components/prism-openqasm.min.js" => "../../static/components/prism-openqasm.min.js",
            "/static/components/prism-oz.min.js" => "../../static/components/prism-oz.min.js",
            "/static/components/prism-parigp.min.js" => "../../static/components/prism-parigp.min.js",
            "/static/components/prism-parser.min.js" => "../../static/components/prism-parser.min.js",
            "/static/components/prism-pascaligo.min.js" => "../../static/components/prism-pascaligo.min.js",
            "/static/components/prism-pascal.min.js" => "../../static/components/prism-pascal.min.js",
            "/static/components/prism-pcaxis.min.js" => "../../static/components/prism-pcaxis.min.js",
            "/static/components/prism-peoplecode.min.js" => "../../static/components/prism-peoplecode.min.js",
            "/static/components/prism-perl.min.js" => "../../static/components/prism-perl.min.js",
            "/static/components/prism-phpdoc.min.js" => "../../static/components/prism-phpdoc.min.js",
            "/static/components/prism-php-extras.min.js" => "../../static/components/prism-php-extras.min.js",
            "/static/components/prism-php.min.js" => "../../static/components/prism-php.min.js",
            "/static/components/prism-plant-uml.min.js" => "../../static/components/prism-plant-uml.min.js",
            "/static/components/prism-plsql.min.js" => "../../static/components/prism-plsql.min.js",
            "/static/components/prism-powerquery.min.js" => "../../static/components/prism-powerquery.min.js",
            "/static/components/prism-powershell.min.js" => "../../static/components/prism-powershell.min.js",
            "/static/components/prism-processing.min.js" => "../../static/components/prism-processing.min.js",
            "/static/components/prism-prolog.min.js" => "../../static/components/prism-prolog.min.js",
            "/static/components/prism-promql.min.js" => "../../static/components/prism-promql.min.js",
            "/static/components/prism-properties.min.js" => "../../static/components/prism-properties.min.js",
            "/static/components/prism-protobuf.min.js" => "../../static/components/prism-protobuf.min.js",
            "/static/components/prism-psl.min.js" => "../../static/components/prism-psl.min.js",
            "/static/components/prism-pug.min.js" => "../../static/components/prism-pug.min.js",
            "/static/components/prism-puppet.min.js" => "../../static/components/prism-puppet.min.js",
            "/static/components/prism-purebasic.min.js" => "../../static/components/prism-purebasic.min.js",
            "/static/components/prism-pure.min.js" => "../../static/components/prism-pure.min.js",
            "/static/components/prism-purescript.min.js" => "../../static/components/prism-purescript.min.js",
            "/static/components/prism-python.min.js" => "../../static/components/prism-python.min.js",
            "/static/components/prism-q.min.js" => "../../static/components/prism-q.min.js",
            "/static/components/prism-qml.min.js" => "../../static/components/prism-qml.min.js",
            "/static/components/prism-qore.min.js" => "../../static/components/prism-qore.min.js",
            "/static/components/prism-qsharp.min.js" => "../../static/components/prism-qsharp.min.js",
            "/static/components/prism-racket.min.js" => "../../static/components/prism-racket.min.js",
            "/static/components/prism-reason.min.js" => "../../static/components/prism-reason.min.js",
            "/static/components/prism-regex.min.js" => "../../static/components/prism-regex.min.js",
            "/static/components/prism-rego.min.js" => "../../static/components/prism-rego.min.js",
            "/static/components/prism-renpy.min.js" => "../../static/components/prism-renpy.min.js",
            "/static/components/prism-rescript.min.js" => "../../static/components/prism-rescript.min.js",
            "/static/components/prism-rest.min.js" => "../../static/components/prism-rest.min.js",
            "/static/components/prism-rip.min.js" => "../../static/components/prism-rip.min.js",
            "/static/components/prism-r.min.js" => "../../static/components/prism-r.min.js",
            "/static/components/prism-roboconf.min.js" => "../../static/components/prism-roboconf.min.js",
            "/static/components/prism-robotframework.min.js" => "../../static/components/prism-robotframework.min.js",
            "/static/components/prism-ruby.min.js" => "../../static/components/prism-ruby.min.js",
            "/static/components/prism-rust.min.js" => "../../static/components/prism-rust.min.js",
            "/static/components/prism-sas.min.js" => "../../static/components/prism-sas.min.js",
            "/static/components/prism-sass.min.js" => "../../static/components/prism-sass.min.js",
            "/static/components/prism-scala.min.js" => "../../static/components/prism-scala.min.js",
            "/static/components/prism-scheme.min.js" => "../../static/components/prism-scheme.min.js",
            "/static/components/prism-scss.min.js" => "../../static/components/prism-scss.min.js",
            "/static/components/prism-shell-session.min.js" => "../../static/components/prism-shell-session.min.js",
            "/static/components/prism-smali.min.js" => "../../static/components/prism-smali.min.js",
            "/static/components/prism-smalltalk.min.js" => "../../static/components/prism-smalltalk.min.js",
            "/static/components/prism-smarty.min.js" => "../../static/components/prism-smarty.min.js",
            "/static/components/prism-sml.min.js" => "../../static/components/prism-sml.min.js",
            "/static/components/prism-solidity.min.js" => "../../static/components/prism-solidity.min.js",
            "/static/components/prism-solution-file.min.js" => "../../static/components/prism-solution-file.min.js",
            "/static/components/prism-soy.min.js" => "../../static/components/prism-soy.min.js",
            "/static/components/prism-sparql.min.js" => "../../static/components/prism-sparql.min.js",
            "/static/components/prism-splunk-spl.min.js" => "../../static/components/prism-splunk-spl.min.js",
            "/static/components/prism-sqf.min.js" => "../../static/components/prism-sqf.min.js",
            "/static/components/prism-sql.min.js" => "../../static/components/prism-sql.min.js",
            "/static/components/prism-squirrel.min.js" => "../../static/components/prism-squirrel.min.js",
            "/static/components/prism-stan.min.js" => "../../static/components/prism-stan.min.js",
            "/static/components/prism-stata.min.js" => "../../static/components/prism-stata.min.js",
            "/static/components/prism-stylus.min.js" => "../../static/components/prism-stylus.min.js",
            "/static/components/prism-supercollider.min.js" => "../../static/components/prism-supercollider.min.js",
            "/static/components/prism-swift.min.js" => "../../static/components/prism-swift.min.js",
            "/static/components/prism-systemd.min.js" => "../../static/components/prism-systemd.min.js",
            "/static/components/prism-t4-cs.min.js" => "../../static/components/prism-t4-cs.min.js",
            "/static/components/prism-t4-templating.min.js" => "../../static/components/prism-t4-templating.min.js",
            "/static/components/prism-t4-vb.min.js" => "../../static/components/prism-t4-vb.min.js",
            "/static/components/prism-tap.min.js" => "../../static/components/prism-tap.min.js",
            "/static/components/prism-tcl.min.js" => "../../static/components/prism-tcl.min.js",
            "/static/components/prism-textile.min.js" => "../../static/components/prism-textile.min.js",
            "/static/components/prism-toml.min.js" => "../../static/components/prism-toml.min.js",
            "/static/components/prism-tremor.min.js" => "../../static/components/prism-tremor.min.js",
            "/static/components/prism-tsx.min.js" => "../../static/components/prism-tsx.min.js",
            "/static/components/prism-tt2.min.js" => "../../static/components/prism-tt2.min.js",
            "/static/components/prism-turtle.min.js" => "../../static/components/prism-turtle.min.js",
            "/static/components/prism-twig.min.js" => "../../static/components/prism-twig.min.js",
            "/static/components/prism-typescript.min.js" => "../../static/components/prism-typescript.min.js",
            "/static/components/prism-typoscript.min.js" => "../../static/components/prism-typoscript.min.js",
            "/static/components/prism-unrealscript.min.js" => "../../static/components/prism-unrealscript.min.js",
            "/static/components/prism-uorazor.min.js" => "../../static/components/prism-uorazor.min.js",
            "/static/components/prism-uri.min.js" => "../../static/components/prism-uri.min.js",
            "/static/components/prism-vala.min.js" => "../../static/components/prism-vala.min.js",
            "/static/components/prism-vbnet.min.js" => "../../static/components/prism-vbnet.min.js",
            "/static/components/prism-velocity.min.js" => "../../static/components/prism-velocity.min.js",
            "/static/components/prism-verilog.min.js" => "../../static/components/prism-verilog.min.js",
            "/static/components/prism-vhdl.min.js" => "../../static/components/prism-vhdl.min.js",
            "/static/components/prism-vim.min.js" => "../../static/components/prism-vim.min.js",
            "/static/components/prism-visual-basic.min.js" => "../../static/components/prism-visual-basic.min.js",
            "/static/components/prism-v.min.js" => "../../static/components/prism-v.min.js",
            "/static/components/prism-warpscript.min.js" => "../../static/components/prism-warpscript.min.js",
            "/static/components/prism-wasm.min.js" => "../../static/components/prism-wasm.min.js",
            "/static/components/prism-web-idl.min.js" => "../../static/components/prism-web-idl.min.js",
            "/static/components/prism-wgsl.min.js" => "../../static/components/prism-wgsl.min.js",
            "/static/components/prism-wiki.min.js" => "../../static/components/prism-wiki.min.js",
            "/static/components/prism-wolfram.min.js" => "../../static/components/prism-wolfram.min.js",
            "/static/components/prism-wren.min.js" => "../../static/components/prism-wren.min.js",
            "/static/components/prism-xeora.min.js" => "../../static/components/prism-xeora.min.js",
            "/static/components/prism-xml-doc.min.js" => "../../static/components/prism-xml-doc.min.js",
            "/static/components/prism-xojo.min.js" => "../../static/components/prism-xojo.min.js",
            "/static/components/prism-xquery.min.js" => "../../static/components/prism-xquery.min.js",
            "/static/components/prism-yaml.min.js" => "../../static/components/prism-yaml.min.js",
            "/static/components/prism-yang.min.js" => "../../static/components/prism-yang.min.js",
            "/static/components/prism-zig.min.js" => "../../static/components/prism-zig.min.js"
        },
    }
}
