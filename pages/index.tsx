import Link from '@/components/Link'
import { PageSEO } from '@/components/SEO'
import Tag from '@/components/Tag'
import siteMetadata from '@/data/siteMetadata'
import { getAllFilesFrontMatter } from '@/lib/mdx'
import formatDate from '@/lib/utils/formatDate'
import { GetStaticProps, InferGetStaticPropsType } from 'next'
import { PostFrontMatter } from 'types/PostFrontMatter'
import NewsletterForm from '@/components/NewsletterForm'
import Splashscreen from '@/components/Splashscreen'
import FullLogo from '@/data/fullLogo.svg'
import { getMembersFiles } from '@/data/membersData'
import contestsData from '@/data/contestsData'
import { MdxFile } from 'types/FrontMatter'

const MAX_DISPLAY = 5

export const getStaticProps: GetStaticProps<{
  posts: PostFrontMatter[]
  members: MdxFile[]
}> = async () => {
  const posts = await getAllFilesFrontMatter('blog')
  const members = await getMembersFiles()

  return { props: { posts, members } }
}

export default function Home({ posts, members }: InferGetStaticPropsType<typeof getStaticProps>) {
  const currentMembers = members.filter((m) => !m.frontMatter.retired).length
  return (
    <>
      <PageSEO title={siteMetadata.title} description={siteMetadata.description} />
      <Splashscreen />
      <div className="divide-y divide-gray-200 dark:divide-gray-700">
        <div className="pt-8 pb-8 text-center">
          {/* <FullLogo
            // viewBox="0 0 509 202"
            className="mx-auto mb-8"
            style={{ width: 'clamp(35%, 400px, calc(100% - 20px))' }}
            alt="SNI"
          /> */}
          <h1 className="text-3xl font-extrabold leading-9 tracking-tight text-gray-900 dark:text-gray-100 sm:text-4xl sm:leading-10 md:text-6xl md:leading-14">
            Serikat Newbie Indonesia
          </h1>
          <h2 className="text-xl leading-9 tracking-tight text-gray-500 dark:text-gray-400 sm:text-2xl sm:leading-10 md:text-2xl md:leading-14">
            Ora CTF, yo sakau
          </h2>
        </div>
        <div className="pt-8 pb-8 space-y-2 md:space-y-5">
          <p className="text-lg leading-7 text-center text-gray-500 dark:text-gray-400">
            <code
              aria-label={`Serikat Newbie Indonesia [SNI] is a CTF team with ${currentMembers} active members, and activeley played in weekend ctfs.`}
            >
              {`We play every weekend to sharpen our knowledge and have fun at the same time! Currently, we are ranked 16th in the world on CTFTime, hold the 1st position in the Indonesian region, and aim to be among the top 10 teams worldwide in CTF (CTFTime)!`}
            </code>
          </p>
        </div>
        <ul className="">
          {!posts.length && 'No posts found.'}
          {posts.slice(0, MAX_DISPLAY).map((frontMatter) => {
            const { slug, date, title, tags } = frontMatter
            return (
              <li key={slug} className="py-6">
                <article>
                  <div className="space-y-2 xl:grid xl:grid-cols-4 xl:space-y-0 xl:items-baseline">
                    <dl>
                      <dt className="sr-only">Published on</dt>
                      <dd className="text-base font-medium leading-6 text-gray-500 dark:text-gray-400">
                        <time dateTime={date as string}>{formatDate(date as string)}</time>
                      </dd>
                    </dl>
                    <div className="space-y-5 xl:col-span-3">
                      <div className="space-y-6">
                        <div>
                          <h2 className="text-2xl font-bold leading-8 tracking-tight">
                            <Link
                              href={`/blog/${slug}`}
                              className="text-gray-900 dark:text-gray-100"
                            >
                              {title}
                            </Link>
                          </h2>
                          <div className="flex flex-wrap">
                            {tags.map((tag) => (
                              <Tag key={tag} text={tag} />
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </article>
              </li>
            )
          })}
        </ul>
      </div>
      {posts.length > MAX_DISPLAY && (
        <div className="flex justify-end text-base font-medium leading-6">
          <Link
            href="/blog"
            className="text-primary-500 hover:text-primary-600 dark:hover:text-primary-400"
            aria-label="all posts"
          >
            All Posts &rarr;
          </Link>
        </div>
      )}
      {siteMetadata.newsletter.provider !== '' && (
        <div className="flex items-center justify-center pt-4">
          <NewsletterForm />
        </div>
      )}
    </>
  )
}
