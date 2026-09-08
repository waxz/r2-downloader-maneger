// Upload this file to your R2 bucket as /renderer.typ so the blog can
// compile Markdown posts. It is referenced by the JavaScript wrapper as:
//   #import "/renderer.typ": render-md-doc
//
// Required Typst packages (fetched from packages.typst.org on first render):
//   @preview/cmarker:0.1.1
//   @preview/mitex:0.2.4
//   @preview/cheq:0.1.0

#import "@preview/cmarker:0.1.1"
#import "@preview/mitex:0.2.4"
#import "@preview/cheq:0.1.0"

#let render-md-doc(
  file-path,
  remove-emoji: true,
  remove-dash: false,
  convert-latex: false,
) = {
  let path-str = if type(file-path) == path {
    let r = repr(file-path)
    r.slice(6, -2)
  } else {
    file-path
  }

  let file-dir = path-str.split("/").slice(0, -1).join("/")
  let base-path = if file-dir != "" { file-dir + "/" } else { "" }

  let md = read(file-path)

  if remove-emoji {
    md = md.replace(regex("[\u{1F300}-\u{1F9FF}\u{1F600}-\u{1F64F}\u{2700}-\u{27BF}]"), "")
    md = md.replace(regex("\p{Extended_Pictographic}"), "")
  }
  if remove-dash {
    md = md.replace("---", "")
  }

  md = md.replace(regex("\s*\n*={3,}\s*\n*"), "=")

  let (meta, md-body) = cmarker.render-with-metadata(
    md,
    metadata-block: "frontmatter-yaml",
    scope: (
      image: (source, alt: none, ..args) => {
        let final-src = if source.starts-with("http") {
          source
        } else {
          base-path + source
        }
        figure(image(final-src, alt: alt, ..args), caption: alt)
      },
    ),
    math: mitex.mitex,
    task-list-marker: checked => if checked { cheq.checked-sym() } else { cheq.unchecked-sym() },
  )

  if meta != none and "title" in meta {
    align(center)[
      #block(width: eval(meta.at("header_width", default: "100%")))[
        #text(
          size: eval(meta.at("title_size", default: "14pt")),
          weight: "bold",
        )[#meta.at("title")]

        #if "subtitle" in meta [
          #v(0.1em)
          #text(size: eval(meta.at("subtitle_size", default: "10pt")))[#meta.at("subtitle")]
        ]

        #if "author" in meta [
          #v(0.1em)
          #text(size: eval(meta.at("author_size", default: "14pt")))[#meta.at("author")]
        ]

        #if "date" in meta [
          #v(0.1em)
          #text(
            size: eval(meta.at("date_size", default: "11pt")),
            fill: rgb("666666"),
          )[#meta.at("date")]
        ]
        #v(0.2em)
      ]
    ]
  }

  md-body
}
