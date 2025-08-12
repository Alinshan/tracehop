#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { traceRedirects } from "./tracer";

const program = new Command();

program
  .name("tracehop")
  .description("Trace URL redirects and view all hops")
  .requiredOption("-u, --url <url>", "URL to trace")
  .option("-m, --max <number>", "Maximum redirects", "10")
  .action(async (options) => {
    const spinner = ora(`Tracing ${options.url}...`).start();
    try {
      const hops = await traceRedirects(options.url, parseInt(options.max));
      spinner.stop();
      console.log(chalk.green("Trace complete:"));
      hops.forEach((hop, index) => {
        console.log(`${index + 1}. ${chalk.cyan(hop.url)} (${hop.status})`);
      });
    } catch (err) {
      spinner.fail("Error tracing URL");
    }
  });

program.parse(process.argv);
